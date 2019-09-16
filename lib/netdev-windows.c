/*
 * Copyright (c) 2014, 2016 VMware, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <config.h>
#include <errno.h>
#include <iphlpapi.h>
#include <cfgmgr32.h>
#include <Rpc.h>
#include <Objbase.h>
#include <combaseapi.h>

#include <net/if.h>
#include <guiddef.h>

#include "coverage.h"
#include "fatal-signal.h"
#include "netdev-provider.h"
#include "openvswitch/ofpbuf.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/shash.h"
#include "svec.h"
#include "openvswitch/vlog.h"
#include "odp-netlink.h"
#include "netlink-socket.h"
#include "netlink.h"

#pragma comment (lib, "Cfgmgr32.lib")
#pragma comment (lib, "Rpcrt4.lib")
#pragma comment (lib, "Ole32.lib")

static GUID zero_guid;

VLOG_DEFINE_THIS_MODULE(netdev_windows);
static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(9999, 5);

enum {
    VALID_IFINDEX           = 1 << 0,
    VALID_ETHERADDR         = 1 << 1,
    VALID_IN                = 1 << 2,
    VALID_MTU               = 1 << 3,
    VALID_POLICING          = 1 << 4,
    VALID_IFFLAG            = 1 << 5,
    VALID_DRVINFO           = 1 << 6,
    VALID_FEATURES          = 1 << 7,
};

/* Caches the information of a netdev. */
struct netdev_windows {
    struct netdev up;
    int32_t dev_type;
    uint32_t port_no;

    unsigned int change_seq;

    unsigned int cache_valid;
    NET_IFINDEX ifindex;
    GUID netcfginstanceid;
    struct eth_addr mac;
    struct eth_addr request_mac_address;
    uint32_t mtu;
    uint32_t request_mtu;
    unsigned int ifi_flags;
    const char *registry_location;
    const char *pnp_id;
};

/* Utility structure for netdev commands. */
struct netdev_windows_netdev_info {
    /* Generic Netlink header. */
    uint8_t cmd;

    /* Information that is relevant to ovs. */
    uint32_t dp_ifindex;
    uint32_t port_no;
    uint32_t ovs_type;

    /* General information of a network device. */
    const char *name;
    struct eth_addr mac_address;
    uint32_t mtu;
    NET_IFINDEX ifindex;
    GUID netcfginstanceid;
    uint32_t ifi_flags;
    const char *registry_location;
    const char *pnp_id;
};
#define ETH_ADDR_FMT_STR_WIN     "%02x%02x%02x%02x%02x%02x"
static int query_netdev(const char *devname,
                        struct netdev_windows_netdev_info *reply,
                        struct ofpbuf **bufp);
static struct netdev *netdev_windows_alloc(void);
static int netdev_windows_init_(void);

/* Generic Netlink family numbers for OVS.
 *
 * Initialized by netdev_windows_init_(). */
static int ovs_win_netdev_family;
struct nl_sock *ovs_win_netdev_sock;
const char* subkey_for_pnp_id =
"SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002bE10318}\\";
const char* subkey_for_enum_id =
"SYSTEM\\CurrentControlSet\\Enum\\";
const char* subkey_for_class_id =
"SYSTEM\\CurrentControlSet\\Control\\Class\\";

static bool
is_netdev_windows_class(const struct netdev_class *netdev_class)
{
    return netdev_class->alloc == netdev_windows_alloc;
}

static struct netdev_windows *
netdev_windows_cast(const struct netdev *netdev_)
{
    ovs_assert(is_netdev_windows_class(netdev_get_class(netdev_)));
    return CONTAINER_OF(netdev_, struct netdev_windows, up);
}

static int
netdev_windows_init_(void)
{
    int error = 0;
    memset(&zero_guid, 0, sizeof(GUID));
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        error = nl_lookup_genl_family(OVS_WIN_NETDEV_FAMILY,
                                      &ovs_win_netdev_family);
        if (error) {
            VLOG_ERR("Generic Netlink family '%s' does not exist. "
                     "The Open vSwitch kernel module is probably not loaded.",
                     OVS_WIN_NETDEV_FAMILY);
        }
        if (!error) {
            /* XXX: Where to close this socket? */
            error = nl_sock_create(NETLINK_GENERIC, &ovs_win_netdev_sock);
        }

        ovsthread_once_done(&once);
    }

    return error;
}

static struct netdev *
netdev_windows_alloc(void)
{
    struct netdev_windows *netdev = xzalloc(sizeof *netdev);
    return netdev ? &netdev->up : NULL;
}

static uint32_t
dp_to_netdev_ifi_flags(uint32_t dp_flags)
{
    uint32_t nd_flags = 0;

    if (dp_flags & OVS_WIN_NETDEV_IFF_UP) {
        nd_flags |= NETDEV_UP;
    }

    nd_flags |= NETDEV_PROMISC;

    return nd_flags;
}

static int
netdev_windows_system_construct(struct netdev *netdev_)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);
    struct netdev_windows_netdev_info info;
    struct ofpbuf *buf;
    int ret;

    /* Query the attributes and runtime status of the netdev. */
    ret = query_netdev(netdev_get_name(&netdev->up), &info, &buf);
    /* "Internal" netdevs do not exist in the kernel yet.  They need to be
     * transformed into a netdev object and passed to dpif_port_add(), which
     * will add them to the kernel.  */
    if (strcmp(netdev_get_type(&netdev->up), "internal") && ret) {
        return ret;
    }
    ofpbuf_delete(buf);

    netdev->dev_type = info.ovs_type;
    netdev->port_no = info.port_no;

    netdev->mac = info.mac_address;
    netdev->cache_valid = VALID_ETHERADDR;

    netdev->mtu = info.mtu;
    netdev->cache_valid |= VALID_MTU;

    netdev->ifi_flags = dp_to_netdev_ifi_flags(info.ifi_flags);
    netdev->cache_valid |= VALID_IFFLAG;

    memcpy(&netdev->netcfginstanceid, &info.netcfginstanceid, sizeof(GUID));
    if (!!memcmp(&netdev->netcfginstanceid, &zero_guid, sizeof(GUID))) {
        netdev->registry_location = xstrdup(info.registry_location);
        netdev->pnp_id = xstrdup(info.pnp_id);
        netdev->cache_valid |= VALID_DRVINFO;
        NET_LUID temp = { 0 };
        ConvertInterfaceGuidToLuid(&netdev->netcfginstanceid, &temp);
        ConvertInterfaceLuidToIndex(&temp, &netdev->ifindex);
        netdev->cache_valid |= VALID_IFINDEX;
    }

    VLOG_DBG("construct device %s, ovs_type: %u.",
        netdev_get_name(&netdev->up), info.ovs_type);
    return 0;
}

static int
netdev_windows_netdev_to_ofpbuf(struct netdev_windows_netdev_info *info,
    struct ofpbuf *buf)
{
    struct ovs_header *ovs_header;
    int error = EINVAL;

    nl_msg_put_genlmsghdr(buf, 0, ovs_win_netdev_family,
        NLM_F_REQUEST | NLM_F_ECHO,
        info->cmd, OVS_WIN_NETDEV_VERSION);

    ovs_header = ofpbuf_put_uninit(buf, sizeof *ovs_header);
    ovs_header->dp_ifindex = info->dp_ifindex;

    if (info->name) {
        GUID test;
        int wchars_num = MultiByteToWideChar(CP_UTF8, 0, info->name, -1, NULL, 0);
        wchar_t* wstr = malloc(wchars_num * sizeof(wchar_t));
        MultiByteToWideChar(CP_UTF8, 0, info->name, -1, wstr, wchars_num);
        if (UuidFromStringA(info->name, &test) == RPC_S_OK) {
            nl_msg_put_unspec(buf, OVS_WIN_NETDEV_ATTR_IF_GUID, &test, sizeof(GUID));
        }
        else if (IIDFromString(wstr, &test) == S_OK) {
            nl_msg_put_unspec(buf, OVS_WIN_NETDEV_ATTR_IF_GUID, &test, sizeof(GUID));
        }
        nl_msg_put_string(buf, OVS_WIN_NETDEV_ATTR_NAME, info->name);
        free(wstr);
        error = 0;
    }

    return error;
}

static void
netdev_windows_info_init(struct netdev_windows_netdev_info *info)
{
    memset(info, 0, sizeof *info);
}

static int
netdev_windows_netdev_from_ofpbuf(struct netdev_windows_netdev_info *info,
    struct ofpbuf *buf)
{
    static const struct nl_policy ovs_netdev_policy[] = {
        [OVS_WIN_NETDEV_ATTR_PORT_NO] = {.type = NL_A_U32 },
        [OVS_WIN_NETDEV_ATTR_TYPE] = {.type = NL_A_U32 },
        [OVS_WIN_NETDEV_ATTR_NAME] = {.type = NL_A_STRING,.max_len = IFNAMSIZ },
        [OVS_WIN_NETDEV_ATTR_MAC_ADDR] = { NL_POLICY_FOR(info->mac_address) },
        [OVS_WIN_NETDEV_ATTR_MTU] = {.type = NL_A_U32 },
        [OVS_WIN_NETDEV_ATTR_IF_INDEX] = {.type = NL_A_U16 },
        [OVS_WIN_NETDEV_ATTR_IF_GUID] = {.type = NL_A_U128},
        [OVS_WIN_NETDEV_ATTR_IF_FLAGS] = {.type = NL_A_U32 },
    };

    netdev_windows_info_init(info);

    struct ofpbuf b = ofpbuf_const_initializer(buf->data, buf->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(&b, sizeof *genl);
    struct ovs_header *ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);

    struct nlattr *a[ARRAY_SIZE(ovs_netdev_policy)];
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != ovs_win_netdev_family
        || !nl_policy_parse(&b, 0, ovs_netdev_policy, a,
            ARRAY_SIZE(ovs_netdev_policy))) {
        return EINVAL;
    }
    info->cmd = genl->cmd;
    info->dp_ifindex = ovs_header->dp_ifindex;
    info->port_no = nl_attr_get_odp_port(a[OVS_WIN_NETDEV_ATTR_PORT_NO]);
    info->ovs_type = nl_attr_get_u32(a[OVS_WIN_NETDEV_ATTR_TYPE]);
    info->name = nl_attr_get_string(a[OVS_WIN_NETDEV_ATTR_NAME]);
    memcpy(&info->mac_address, nl_attr_get_unspec(a[OVS_WIN_NETDEV_ATTR_MAC_ADDR],
        sizeof(info->mac_address)), sizeof(info->mac_address));
    info->mtu = nl_attr_get_u32(a[OVS_WIN_NETDEV_ATTR_MTU]);// -ETH_HEADER_LEN;
    info->ifindex = nl_attr_get_u16(a[OVS_WIN_NETDEV_ATTR_IF_INDEX]);
    info->ifi_flags = nl_attr_get_u32(a[OVS_WIN_NETDEV_ATTR_IF_FLAGS]);
    ovs_u128 temp = nl_attr_get_u128(a[OVS_WIN_NETDEV_ATTR_IF_GUID]);
    memcpy(&info->netcfginstanceid, &temp, sizeof(GUID));
    if (!!memcmp(&info->netcfginstanceid, &zero_guid, sizeof(GUID))) {
        DWORD size = 0;
        char location[256];
        char value[256];
        HKEY hKey;
        snprintf(location, sizeof(location), "%s{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}\\Connection",
            subkey_for_pnp_id, info->netcfginstanceid.Data1, info->netcfginstanceid.Data2, info->netcfginstanceid.Data3,
            info->netcfginstanceid.Data4[0], info->netcfginstanceid.Data4[1], info->netcfginstanceid.Data4[2], info->netcfginstanceid.Data4[3],
            info->netcfginstanceid.Data4[4], info->netcfginstanceid.Data4[5], info->netcfginstanceid.Data4[6], info->netcfginstanceid.Data4[7]);

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, location, 0, KEY_QUERY_VALUE, &hKey) ==
            ERROR_SUCCESS) {
            RegQueryValueEx(hKey, "PnPInstanceId", NULL, NULL, NULL, &size);
            if (RegQueryValueEx(hKey, "PnPInstanceId", NULL, NULL, (BYTE *)value, &size) !=
                ERROR_SUCCESS)
            {
                VLOG_ERR("Could not get PnPInstanceId for port: %s", info->name);
            }
            info->pnp_id = xstrdup(value);
            RegCloseKey(hKey);
            snprintf(location, sizeof(location), "%s%s", subkey_for_enum_id, value);
            if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, location, 0, KEY_QUERY_VALUE, &hKey) ==
                ERROR_SUCCESS) {
                RegQueryValueEx(hKey, "Driver", NULL, NULL, NULL, &size);
                if (RegQueryValueEx(hKey, "Driver", NULL, NULL, (BYTE *)value, &size) !=
                    ERROR_SUCCESS)
                {
                    VLOG_ERR("Could not get Driver for port: %s", info->name);
                }
            }
            RegCloseKey(hKey);
            snprintf(location, sizeof(location), "%s%s", subkey_for_class_id, value);
            info->registry_location = xstrdup(location);
        }
    }

exit:
    return 0;
}

static int
query_netdev(const char *devname,
             struct netdev_windows_netdev_info *info,
             struct ofpbuf **bufp)
{
    int error = 0;
    struct ofpbuf *request_buf;

    ovs_assert(info != NULL);
    netdev_windows_info_init(info);

    error = netdev_windows_init_();
    if (error) {
        if (info) {
            *bufp = NULL;
            netdev_windows_info_init(info);
        }
        return error;
    }

    request_buf = ofpbuf_new(1024);
    info->cmd = OVS_WIN_NETDEV_CMD_GET;
    info->name = devname;
    error = netdev_windows_netdev_to_ofpbuf(info, request_buf);
    if (error) {
        ofpbuf_delete(request_buf);
        return error;
    }

    error = nl_transact(NETLINK_GENERIC, request_buf, bufp);
    ofpbuf_delete(request_buf);

    if (info) {
        if (!error) {
            error = netdev_windows_netdev_from_ofpbuf(info, *bufp);
        }
        if (error) {
            netdev_windows_info_init(info);
            ofpbuf_delete(*bufp);
            *bufp = NULL;
        }
    }

    return error;
}

static void
netdev_windows_destruct(struct netdev *netdev_)
{

}

static void
netdev_windows_dealloc(struct netdev *netdev_)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);
    free(netdev);
}

static int
netdev_windows_get_etheraddr(const struct netdev *netdev_,
                             struct eth_addr *mac)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);

    ovs_assert((netdev->cache_valid & VALID_ETHERADDR) != 0);
    if (netdev->cache_valid & VALID_ETHERADDR) {
        *mac = netdev->mac;
    } else {
        return EINVAL;
    }
    return 0;
}

static int
netdev_windows_get_ifindex(const struct netdev *netdev_)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);

    //ovs_assert((netdev->cache_valid & VALID_IFINDEX) != 0);

    if (!(netdev->cache_valid & VALID_IFINDEX)) {
        return EOPNOTSUPP;
    }

    return netdev->ifindex;
}

static int
netdev_windows_get_mtu(const struct netdev *netdev_, int *mtup)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);

    ovs_assert((netdev->cache_valid & VALID_MTU) != 0);
    if (netdev->cache_valid & VALID_MTU) {
        *mtup = netdev->mtu;
    } else {
        return ENOTSUP;
    }
    return 0;
}

static int
netdev_windows_set_mtu(struct netdev *netdev_, int mtu)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);
    DWORD ret_val = 0;

    if (!strcmp(netdev_get_type(&netdev->up), "internal")) {
        /* We need the value once the adapter is enabled */
        netdev->request_mtu = mtu;
    }
    if (netdev->mtu == mtu) {
        ret_val = 0;
        goto exit;
    }

    if (!(netdev->cache_valid & VALID_IFINDEX)) {
        ret_val = ENOTSUP;
        goto exit;
    }

    MIB_IPINTERFACE_ROW change;
    InitializeIpInterfaceEntry(&change);
    change.InterfaceIndex = netdev->ifindex;
    change.Family = AF_INET;

    ret_val = GetIpInterfaceEntry(&change);
    if (ret_val != NO_ERROR) {
        ret_val = ENODEV;
        goto exit;
    }
    change.Family = AF_INET;
    change.SitePrefixLength = 0;

    change.NlMtu = mtu;
    ret_val = SetIpInterfaceEntry(&change);
    if (ret_val == NO_ERROR) {
        /* Not all drivers set the error code properly.
           So we reverify if the change actually took place. */
        ret_val = GetIpInterfaceEntry(&change);
        if (ret_val == NO_ERROR && change.NlMtu != mtu) {
            VLOG_ERR("The requested MTU could not be actually set.");
            ret_val = ENOTSUP;
            goto exit;
        }
        netdev->mtu = mtu;
    }

exit:
    return ret_val;
}

/* This functionality is not really required by the datapath.
 * But vswitchd bringup expects this to be implemented. */
static int
netdev_windows_set_etheraddr(const struct netdev *netdev_,
                             const struct eth_addr mac)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);

    if (!eth_addr_compare_3way(netdev->mac, mac)) {
        return 0;
    }

    if (netdev->cache_valid & VALID_DRVINFO) {
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, netdev->registry_location, 0, KEY_ALL_ACCESS, &hKey) ==
            ERROR_SUCCESS) {
            char value[ETH_ADDR_STRLEN];
            snprintf(value, sizeof(value), ETH_ADDR_FMT_STR_WIN, ETH_ADDR_ARGS(mac));
            RegSetValueEx(hKey, "NetworkAddress", 0, REG_SZ, (LPBYTE)value, strlen(value));
            RegCloseKey(hKey);
            netdev->mac = mac;
            // restart the adapter
            CONFIGRET cr = CR_SUCCESS;
            DEVINST Devinst;
            cr = CM_Locate_DevNode(&Devinst,
                netdev->pnp_id,
                CM_LOCATE_DEVNODE_NORMAL);

            if (cr != CR_SUCCESS) {
                return -ENOTSUP;
            }

            cr = CM_Query_And_Remove_SubTree(Devinst,
                NULL,
                NULL,
                0,
                CM_REMOVE_NO_RESTART);

            if (cr != CR_SUCCESS) {
                return -ENOTSUP;
            }

            cr = CM_Setup_DevNode(Devinst,
                CM_SETUP_DEVNODE_READY);

            if (cr != CR_SUCCESS) {
                return -ENOTSUP;
            }
        }
        else
            return -ENOTSUP;
    }


    if (!strcmp(netdev_get_type(&netdev->up), "internal")) {
        /* We need the value once the adapter is enabled */
        netdev->request_mac_address = mac;
        return 0;
    }

    return 0;
}

/* This functionality is not really required by the datapath.
 * But vswitchd bringup expects this to be implemented. */
static int
netdev_windows_update_flags(struct netdev *netdev_,
                            enum netdev_flags off,
                            enum netdev_flags on,
                            enum netdev_flags *old_flagsp)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);

    ovs_assert((netdev->cache_valid & VALID_IFFLAG) != 0);

    if (on || off) {
        if (on == netdev->ifi_flags) {
            *old_flagsp = netdev->ifi_flags;
            return 0;
        }
        /* Setting the interface flags is not supported. */
        return EOPNOTSUPP;
    } else {
        *old_flagsp = netdev->ifi_flags;
        return 0;
    }
}

/* Looks up in the ARP table entry for a given 'ip'. If it is found, the
 * corresponding MAC address will be copied in 'mac' and return 0. If no
 * matching entry is found or an error occurs it will log it and return ENXIO.
 */
static int
netdev_windows_arp_lookup(const struct netdev *netdev,
                          ovs_be32 ip, struct eth_addr *mac)
{
    PMIB_IPNETTABLE arp_table = NULL;
    /* The buffer length of all ARP entries */
    uint32_t buffer_length = 0;
    uint32_t ret_val = 0;
    uint32_t counter = 0;

    ret_val = GetIpNetTable(arp_table, &buffer_length, false);

    if (ret_val != ERROR_INSUFFICIENT_BUFFER ) {
        VLOG_ERR("Call to GetIpNetTable failed with error: %s",
                 ovs_format_message(ret_val));
        return ENXIO;
    }

    arp_table = (MIB_IPNETTABLE *) xmalloc(buffer_length);

    ret_val = GetIpNetTable(arp_table, &buffer_length, false);

    if (ret_val == NO_ERROR) {
        for (counter = 0; counter < arp_table->dwNumEntries; counter++) {
            if (arp_table->table[counter].dwAddr == ip) {
                memcpy(mac, arp_table->table[counter].bPhysAddr, ETH_ADDR_LEN);

                free(arp_table);
                return 0;
            }
        }
    } else {
        VLOG_ERR("Call to GetIpNetTable failed with error: %s",
                 ovs_format_message(ret_val));
    }

    free(arp_table);
    return ENXIO;
}

static int
netdev_windows_get_next_hop(const struct in_addr *host,
                            struct in_addr *next_hop,
                            char **netdev_name)
{
    uint32_t ret_val = 0;
    /* The buffer length of all addresses */
    uint32_t buffer_length = 0;
    PIP_ADAPTER_ADDRESSES all_addr = NULL;
    PIP_ADAPTER_ADDRESSES cur_addr = NULL;

    ret_val = GetAdaptersAddresses(AF_INET,
                                   GAA_FLAG_INCLUDE_PREFIX |
                                   GAA_FLAG_INCLUDE_GATEWAYS,
                                   NULL, NULL, &buffer_length);

    if (ret_val != ERROR_BUFFER_OVERFLOW ) {
        VLOG_ERR("Call to GetAdaptersAddresses failed with error: %s",
                 ovs_format_message(ret_val));
        return ENXIO;
    }

    all_addr = (IP_ADAPTER_ADDRESSES *) xmalloc(buffer_length);

    ret_val = GetAdaptersAddresses(AF_INET,
                                   GAA_FLAG_INCLUDE_PREFIX |
                                   GAA_FLAG_INCLUDE_GATEWAYS,
                                   NULL, all_addr, &buffer_length);

    if (ret_val == NO_ERROR) {
        cur_addr = all_addr;
        while (cur_addr) {
            if(cur_addr->FirstGatewayAddress &&
               cur_addr->FirstGatewayAddress->Address.lpSockaddr) {
                char dev_name[IFNAMSIZ];

                if (WideCharToMultiByte(CP_UTF8, 0, cur_addr->FriendlyName, -1, dev_name,
                    IFNAMSIZ, NULL, NULL)) {
                    struct sockaddr_in *ipv4 = (struct sockaddr_in *)
                                           cur_addr->FirstGatewayAddress->Address.lpSockaddr;
                    next_hop->s_addr = ipv4->sin_addr.S_un.S_addr;
                    *netdev_name = xstrdup(dev_name);

                    free(all_addr);


                    return 0;
                }
            }

            cur_addr = cur_addr->Next;
        }
    } else {
        VLOG_ERR("Call to GetAdaptersAddresses failed with error: %s",
                 ovs_format_message(ret_val));
    }

    if (all_addr) {
        free(all_addr);
    }
    return ENXIO;
}
/*    UINT32 portNo;
    OVS_VPORT_TYPE ovsType;
    UINT32 upcallPid;
    CHAR ovsName[OVS_MAX_PORT_NAME_LENGTH];
    UINT32 type;*/
/* Returns a NETLINK_ROUTE socket listening for RTNLGRP_LINK,
 * RTNLGRP_IPV4_IFADDR and RTNLGRP_IPV6_IFADDR changes, or NULL
 * if no such socket could be created. */
typedef struct _OVS_VPORT_EVENT_ENTRY {
    UINT32 portNo;
    OVS_VPORT_TYPE ovsType;
    UINT32 upcallPid;
    CHAR ovsName[IFNAMSIZ];
    UINT32 type;
} OVS_VPORT_EVENT_ENTRY, *POVS_VPORT_EVENT_ENTRY;

static int
netdev_windows_netdev_from_ofpbuf2(struct netdev_windows_netdev_info *info,
                                  struct ofpbuf *buf)
{
    POVS_VPORT_EVENT_ENTRY bla = NULL;

    netdev_windows_info_init(info);
    static const struct nl_policy ovs_netdev_policy[] = {
        [OVS_WIN_NETDEV_ATTR_PORT_NO] = {.type = NL_A_U32 },
        [OVS_WIN_NETDEV_ATTR_TYPE] = {.type = NL_A_U32 },
        [OVS_VPORT_ATTR_UPCALL_PID] = {.type = NL_A_U32 },
        [OVS_WIN_NETDEV_ATTR_NAME] = {.type = NL_A_STRING,.max_len = IFNAMSIZ },
    };

    netdev_windows_info_init(info);

    struct ofpbuf b = ofpbuf_const_initializer(buf->data, buf->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(&b, sizeof *genl);
    struct ovs_header *ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);
    struct nlattr *a[ARRAY_SIZE(ovs_netdev_policy)];

    if (!nlmsg || !genl || !ovs_header
        || !nl_policy_parse(&b, 0, ovs_netdev_policy, a,
                            ARRAY_SIZE(ovs_netdev_policy))) {
        return EINVAL;
    }

    info->port_no = nl_attr_get_odp_port(a[OVS_WIN_NETDEV_ATTR_PORT_NO]);
    info->ovs_type = nl_attr_get_u32(a[OVS_WIN_NETDEV_ATTR_TYPE]);
    info->name = nl_attr_get_string(a[OVS_WIN_NETDEV_ATTR_NAME]);
    struct netdev *netdev_ = NULL;
    netdev_ = netdev_from_name(info->name);
    HANDLE bla_event = OpenEventA(EVENT_ALL_ACCESS, FALSE, "interface_changed");
    if (netdev_ && is_netdev_windows_class(netdev_->netdev_class)) {
        struct netdev_windows *netdev = netdev_windows_cast(netdev_);
        struct netdev_windows_netdev_info info1;
        struct ofpbuf *buf1;
        int ret;

        /* Query the attributes and runtime status of the netdev. */
        ret = query_netdev(netdev_get_name(&netdev->up), &info1, &buf1);
        /* "Internal" netdevs do not exist in the kernel yet.  They need to be
         * transformed into a netdev object and passed to dpif_port_add(), which
         * will add them to the kernel.  */
        if (ret) {
            return ret;
        }
        ofpbuf_delete(buf1);

        netdev->dev_type = info1.ovs_type;
        netdev->port_no = info1.port_no;

        netdev->mac = info1.mac_address;
        netdev->cache_valid = VALID_ETHERADDR;

        netdev->mtu = info1.mtu;
        netdev->cache_valid |= VALID_MTU;

        netdev->ifi_flags = dp_to_netdev_ifi_flags(info1.ifi_flags);
        netdev->cache_valid |= VALID_IFFLAG;

        memcpy(&netdev->netcfginstanceid, &info1.netcfginstanceid, sizeof(GUID));
        if (!!memcmp(&netdev->netcfginstanceid, &zero_guid, sizeof(GUID))) {
            netdev->registry_location = xstrdup(info1.registry_location);
            netdev->pnp_id = xstrdup(info1.pnp_id);
            netdev->cache_valid |= VALID_DRVINFO;
            NET_LUID temp = { 0 };
            ConvertInterfaceGuidToLuid(&netdev->netcfginstanceid, &temp);
            ConvertInterfaceLuidToIndex(&temp, &netdev->ifindex);
            netdev->cache_valid |= VALID_IFINDEX;
            if (!eth_addr_is_zero(netdev->request_mac_address)) {
                netdev_windows_set_etheraddr(netdev_, netdev->request_mac_address);
            }
            if (netdev->request_mtu) {
                netdev_windows_set_mtu(netdev_, netdev->request_mtu);
            }
        }

        netdev_change_seq_changed(&netdev->up);
    } else {
        if (bla_event) {
            SetEvent(bla_event);
        }
    }
    if (netdev_) {
        netdev_close(netdev_);
    }
    return 0;
}

static struct nl_sock *
netdev_windows_notify_sock(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    int error = 0;
    static struct nl_sock *sock = NULL;

    if (ovsthread_once_start(&once)) {
        error = nl_sock_create(NETLINK_GENERIC, &sock);
        if (!error) {
            error = nl_sock_join_mcgroup(sock, OVS_WIN_NL_VPORT_MCGRP_ID);
            if (error) {
                VLOG_ERR("netdev_windows_notify_sock : could not join the mcgroup");
                nl_sock_destroy(sock);
                sock = NULL;
            }
        }
        ovsthread_once_done(&once);
    }

    return sock;
}

void
netdev_windows_run(const struct netdev_class *netdev_class OVS_UNUSED)
{
    struct nl_sock *sock;
    int error = 0;
    sock = netdev_windows_notify_sock();
    if (!sock) {
        return;
    }

    do {
        uint64_t buf_stub[4096 / 8];
        struct ofpbuf buf;

        ofpbuf_use_stub(&buf, buf_stub, sizeof buf_stub);
        error = nl_sock_recv(sock, &buf, NULL, false);
        if (!error) {
            struct netdev_windows_netdev_info info;
            netdev_windows_info_init(&info);
            error = netdev_windows_netdev_from_ofpbuf2(&info, &buf);
        } else if (error != EAGAIN) {
            static struct vlog_rate_limit rll = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rll, "error reading or parsing netlink (%s)",
                         ovs_strerror(error));
        }
        ofpbuf_uninit(&buf);
    } while (!error);

}

static void
netdev_windows_wait(const struct netdev_class *netdev_class OVS_UNUSED)
{

}

/* Registers with the poll loop to wake up from the next call to poll_block()
 * when the packet transmission queue has sufficient room to transmit a packet
 * with netdev_send().
 *
 * The kernel maintains a packet transmission queue, so the client is not
 * expected to do additional queuing of packets.  Thus, this function is
 * unlikely to ever be used.  It is included for completeness. */
static void
netdev_windows_send_wait(struct netdev *netdev, int qid OVS_UNUSED)
{
}


static int
netdev_windows_internal_construct(struct netdev *netdev_)
{
    return netdev_windows_system_construct(netdev_);
}

static int
netdev_windows_set_in4(struct netdev *netdev_, struct in_addr address,
    struct in_addr netmask)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);
    int error;
    DWORD lastError = 0;
    SOCKADDR_IN localAddress;
    MIB_UNICASTIPADDRESS_ROW ipRow;
    localAddress.sin_family = AF_INET;
    localAddress.sin_addr.S_un.S_addr = address.s_addr;
    ipRow.InterfaceIndex = netdev->ifindex;
    ipRow.Address.si_family = AF_INET;

    // Initialize the row
    InitializeUnicastIpAddressEntry(&ipRow);

    ipRow.InterfaceIndex = netdev->ifindex;
    ipRow.Address.Ipv4 = localAddress;
    error = ConvertIpv4MaskToLength(netmask.s_addr, &ipRow.OnLinkPrefixLength);

    if (!error) {
        error = CreateUnicastIpAddressEntry(&ipRow);
    }

    return error;
}


#define NETDEV_WINDOWS_CLASS(NAME, CONSTRUCT)                           \
{                                                                       \
    .type               = NAME,                                         \
    .is_pmd             = false,                                        \
    .alloc              = netdev_windows_alloc,                         \
    .construct          = CONSTRUCT,                                    \
    .destruct           = netdev_windows_destruct,                      \
    .dealloc            = netdev_windows_dealloc,                       \
    .get_etheraddr      = netdev_windows_get_etheraddr,                 \
    .get_ifindex        = netdev_windows_get_ifindex,                   \
    .set_etheraddr      = netdev_windows_set_etheraddr,                 \
    .get_mtu            = netdev_windows_get_mtu,                       \
    .set_mtu            = netdev_windows_set_mtu,                       \
    .update_flags       = netdev_windows_update_flags,                  \
    .get_next_hop       = netdev_windows_get_next_hop,                  \
    .arp_lookup         = netdev_windows_arp_lookup,                    \
    .set_in4            = netdev_windows_set_in4,                       \
    .run                = netdev_windows_run,                           \
    .wait               = netdev_windows_wait,                          \
    .send_wait          = netdev_windows_send_wait,                     \
}

const struct netdev_class netdev_windows_class =
    NETDEV_WINDOWS_CLASS(
        "system",
        netdev_windows_system_construct);

const struct netdev_class netdev_internal_class =
    NETDEV_WINDOWS_CLASS(
        "internal",
        netdev_windows_internal_construct);
