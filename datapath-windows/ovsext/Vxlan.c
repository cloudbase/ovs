/*
 * Copyright (c) 2014 VMware, Inc.
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

#include "precomp.h"
#include "Atomic.h"
#include "NetProto.h"
#include "Switch.h"
#include "Vport.h"
#include "Flow.h"
#include "Vxlan.h"
#include "IpHelper.h"
#include "Checksum.h"
#include "User.h"
#include "PacketIO.h"
#include "Flow.h"
#include "PacketParser.h"

#pragma warning( push )
#pragma warning( disable:4127 )


#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_VXLAN
#include "Debug.h"

/* Helper macro to check if a VXLAN ID is valid. */
#define VXLAN_ID_IS_VALID(vxlanID) (0 < (vxlanID) && (vxlanID) <= 0xffffff)
#define VXLAN_TUNNELID_TO_VNI(_tID)   (UINT32)(((UINT64)(_tID)) >> 40)
#define VXLAN_VNI_TO_TUNNELID(_vni) (((UINT64)(_vni)) << 40)
#define IP_DF_NBO 0x0040
#define VXLAN_DEFAULT_TTL 64
#define VXLAN_MULTICAST_TTL 64
#define VXLAN_DEFAULT_INSTANCE_ID 1

/* Move to a header file */
extern POVS_SWITCH_CONTEXT gOvsSwitchContext;

/*
 *----------------------------------------------------------------------------
 * This function verifies if the VXLAN tunnel already exists, in order to
 * avoid sending a duplicate request to the WFP base filtering engine.
 *----------------------------------------------------------------------------
 */
static BOOLEAN
OvsIsTunnelFilterCreated(POVS_SWITCH_CONTEXT switchContext,
                         UINT16 udpPortDest)
{
    for (UINT hash = 0; hash < OVS_MAX_VPORT_ARRAY_SIZE; hash++) {
        PLIST_ENTRY head, link, next;

        head = &(switchContext->portNoHashArray[hash & OVS_VPORT_MASK]);
        LIST_FORALL_SAFE(head, link, next) {
            POVS_VPORT_ENTRY vport = NULL;
            POVS_VXLAN_VPORT vxlanPort = NULL;
            vport = CONTAINING_RECORD(link, OVS_VPORT_ENTRY, portNoLink);
            vxlanPort = (POVS_VXLAN_VPORT)vport->priv;
            if (vxlanPort) {
                if ((udpPortDest == vxlanPort->dstPort)) {
                    /* The VXLAN tunnel was already created. */
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

/*
 *----------------------------------------------------------------------------
 * This function allocates and initializes the OVS_VXLAN_VPORT. The function
 * also creates a WFP tunnel filter for the necessary destination port. The
 * tunnel filter create request is passed to the tunnel filter threads that
 * will complete the request at a later time when IRQL is lowered to
 * PASSIVE_LEVEL.
 *
 * udpDestPort: the vxlan is set as payload to a udp frame. If the destination
 * port of an udp frame is udpDestPort, we understand it to be vxlan.
 *----------------------------------------------------------------------------
 */
NTSTATUS
OvsInitVxlanTunnel(PIRP irp,
                   POVS_VPORT_ENTRY vport,
                   UINT16 udpDestPort,
                   PFNTunnelVportPendingOp callback,
                   PVOID tunnelContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    POVS_VXLAN_VPORT vxlanPort = NULL;

    vxlanPort = OvsAllocateMemoryWithTag(sizeof (*vxlanPort),
                                         OVS_VXLAN_POOL_TAG);
    if (vxlanPort == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(vxlanPort, sizeof(*vxlanPort));
    vxlanPort->dstPort = udpDestPort;
    vport->priv = (PVOID)vxlanPort;

    if (!OvsIsTunnelFilterCreated(gOvsSwitchContext, udpDestPort)) {
        status = OvsTunnelFilterCreate(irp,
                                       udpDestPort,
                                       &vxlanPort->filterID,
                                       callback,
                                       tunnelContext);
    } else {
        status = STATUS_OBJECT_NAME_EXISTS;
    }

    return status;
}

/*
 *----------------------------------------------------------------------------
 * This function releases the OVS_VXLAN_VPORT. The function also deletes the
 * WFP tunnel filter previously created. The tunnel filter delete request is
 * passed to the tunnel filter threads that will complete the request at a
 * later time when IRQL is lowered to PASSIVE_LEVEL.
 *----------------------------------------------------------------------------
 */
NTSTATUS
OvsCleanupVxlanTunnel(PIRP irp,
                      POVS_VPORT_ENTRY vport,
                      PFNTunnelVportPendingOp callback,
                      PVOID tunnelContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    POVS_VXLAN_VPORT vxlanPort = NULL;

    if (vport->ovsType != OVS_VPORT_TYPE_VXLAN ||
        vport->priv == NULL) {
        return STATUS_SUCCESS;
    }

    vxlanPort = (POVS_VXLAN_VPORT)vport->priv;

    if (vxlanPort->filterID != 0) {
        status = OvsTunnelFilterDelete(irp,
                                       vxlanPort->filterID,
                                       callback,
                                       tunnelContext);
    } else {
        OvsFreeMemoryWithTag(vport->priv, OVS_VXLAN_POOL_TAG);
        vport->priv = NULL;
    }

    return status;
}

static __inline VOID *
GetStartAddrNBL(const NET_BUFFER_LIST *_pNB)
{
    PMDL curMdl;
    PUINT8 curBuffer;
    PEthHdr curHeader;

    ASSERT(_pNB);

    // Ethernet Header is a guaranteed safe access.
    curMdl = (NET_BUFFER_LIST_FIRST_NB(_pNB))->CurrentMdl;
    curBuffer = MmGetSystemAddressForMdlSafe(curMdl, LowPagePriority);
    if (!curBuffer) {
        return NULL;
    }

    curHeader = (PEthHdr)
        (curBuffer + (NET_BUFFER_LIST_FIRST_NB(_pNB))->CurrentMdlOffset);

    return (VOID *)curHeader;
}

NDIS_STATUS
OvsExtractLayers(const NET_BUFFER_LIST *packet,
                 POVS_PACKET_HDR_INFO layers)
{
    struct Eth_Header *eth;
    UINT8 offset = 0;
    PVOID vlanTagValue;

    layers->value = 0;
    OvsFlowKey flow_temp = { 0 };
    OvsFlowKey* flow = &flow_temp;

    if (OvsPacketLenNBL(packet) < ETH_HEADER_LEN_DIX) {
        flow->l2.keyLen = OVS_WIN_TUNNEL_KEY_SIZE + 8 - flow->l2.offset;
        return NDIS_STATUS_SUCCESS;
    }

    /* Link layer. */
    eth = (Eth_Header *)GetStartAddrNBL((NET_BUFFER_LIST *)packet);
    memcpy(flow->l2.dlSrc, eth->src, ETH_ADDR_LENGTH);
    memcpy(flow->l2.dlDst, eth->dst, ETH_ADDR_LENGTH);

    /*
    * vlan_tci.
    */
    vlanTagValue = NET_BUFFER_LIST_INFO(packet, Ieee8021QNetBufferListInfo);
    if (vlanTagValue) {
        PNDIS_NET_BUFFER_LIST_8021Q_INFO vlanTag =
            (PNDIS_NET_BUFFER_LIST_8021Q_INFO)(PVOID *)&vlanTagValue;
        flow->l2.vlanTci = htons(vlanTag->TagHeader.VlanId | OVSWIN_VLAN_CFI |
            (vlanTag->TagHeader.UserPriority << 13));
    }
    else {
        if (eth->dix.typeNBO == ETH_TYPE_802_1PQ_NBO) {
            Eth_802_1pq_Tag *tag = (Eth_802_1pq_Tag *)&eth->dix.typeNBO;
            flow->l2.vlanTci = ((UINT16)tag->priority << 13) |
                OVSWIN_VLAN_CFI |
                ((UINT16)tag->vidHi << 8) | tag->vidLo;
            offset = sizeof(Eth_802_1pq_Tag);
        }
        else {
            flow->l2.vlanTci = 0;
        }
        /*
        * XXX
        * Please note after this point, src mac and dst mac should
        * not be accessed through eth
        */
        eth = (Eth_Header *)((UINT8 *)eth + offset);
    }

    /*
    * dl_type.
    *
    * XXX assume that at least the first
    * 12 bytes of received packets are mapped.  This code has the stronger
    * assumption that at least the first 22 bytes of 'packet' is mapped (if my
    * arithmetic is right).
    */
    if (ETH_TYPENOT8023(eth->dix.typeNBO)) {
        flow->l2.dlType = eth->dix.typeNBO;
        layers->l3Offset = ETH_HEADER_LEN_DIX + offset;
    }
    else if (OvsPacketLenNBL(packet) >= ETH_HEADER_LEN_802_3 &&
        eth->e802_3.llc.dsap == 0xaa &&
        eth->e802_3.llc.ssap == 0xaa &&
        eth->e802_3.llc.control == ETH_LLC_CONTROL_UFRAME &&
        eth->e802_3.snap.snapOrg[0] == 0x00 &&
        eth->e802_3.snap.snapOrg[1] == 0x00 &&
        eth->e802_3.snap.snapOrg[2] == 0x00) {
        flow->l2.dlType = eth->e802_3.snap.snapType.typeNBO;
        layers->l3Offset = ETH_HEADER_LEN_802_3 + offset;
    }
    else {
        flow->l2.dlType = htons(OVSWIN_DL_TYPE_NONE);
        layers->l3Offset = ETH_HEADER_LEN_DIX + offset;
    }

    flow->l2.keyLen = OVS_WIN_TUNNEL_KEY_SIZE + OVS_L2_KEY_SIZE - flow->l2.offset;
    /* Network layer. */
    if (flow->l2.dlType == htons(ETH_TYPE_IPV4)) {
        struct IPHdr ip_storage;
        const struct IPHdr *nh;
        IpKey *ipKey = &flow->ipKey;

        flow->l2.keyLen += OVS_IP_KEY_SIZE;
        layers->isIPv4 = 1;
        nh = OvsGetIp(packet, layers->l3Offset, &ip_storage);
        if (nh) {
            layers->l4Offset = layers->l3Offset + nh->ihl * 4;

            ipKey->nwSrc = nh->saddr;
            ipKey->nwDst = nh->daddr;
            ipKey->nwProto = nh->protocol;

            ipKey->nwTos = nh->tos;
            if (nh->frag_off & htons(IP_MF | IP_OFFSET)) {
                ipKey->nwFrag = OVSWIN_NW_FRAG_ANY;
                if (nh->frag_off & htons(IP_OFFSET)) {
                    ipKey->nwFrag |= OVSWIN_NW_FRAG_LATER;
                }
            }
            else {
                ipKey->nwFrag = 0;
            }

            ipKey->nwTtl = nh->ttl;
            ipKey->l4.tpSrc = 0;
            ipKey->l4.tpDst = 0;

            if (!(nh->frag_off & htons(IP_OFFSET))) {
                if (ipKey->nwProto == SOCKET_IPPROTO_TCP) {
                    OvsParseTcp(packet, &ipKey->l4, layers);
                }
                else if (ipKey->nwProto == SOCKET_IPPROTO_UDP) {
                    OvsParseUdp(packet, &ipKey->l4, layers);
                }
                else if (ipKey->nwProto == SOCKET_IPPROTO_ICMP) {
                    ICMPHdr icmpStorage;
                    const ICMPHdr *icmp;

                    icmp = OvsGetIcmp(packet, layers->l4Offset, &icmpStorage);
                    if (icmp) {
                        ipKey->l4.tpSrc = htons(icmp->type);
                        ipKey->l4.tpDst = htons(icmp->code);
                        layers->l7Offset = layers->l4Offset + sizeof *icmp;
                    }
                }
            }
        }
        else {
            ((UINT64 *)ipKey)[0] = 0;
            ((UINT64 *)ipKey)[1] = 0;
        }
    }
    else if (flow->l2.dlType == htons(ETH_TYPE_IPV6)) {
        NDIS_STATUS status;
        flow->l2.keyLen += OVS_IPV6_KEY_SIZE;
        status = OvsParseIPv6(packet, flow, layers);
        if (status != NDIS_STATUS_SUCCESS) {
            memset(&flow->ipv6Key, 0, sizeof(Ipv6Key));
            return status;
        }
        layers->isIPv6 = 1;
        flow->ipv6Key.l4.tpSrc = 0;
        flow->ipv6Key.l4.tpDst = 0;
        flow->ipv6Key.pad = 0;

        if (flow->ipv6Key.nwProto == SOCKET_IPPROTO_TCP) {
            OvsParseTcp(packet, &(flow->ipv6Key.l4), layers);
        }
        else if (flow->ipv6Key.nwProto == SOCKET_IPPROTO_UDP) {
            OvsParseUdp(packet, &(flow->ipv6Key.l4), layers);
        }
        else if (flow->ipv6Key.nwProto == SOCKET_IPPROTO_ICMPV6) {
            OvsParseIcmpV6(packet, flow, layers);
            flow->l2.keyLen += (OVS_ICMPV6_KEY_SIZE - OVS_IPV6_KEY_SIZE);
        }
    }
    else if (flow->l2.dlType == htons(ETH_TYPE_ARP)) {
        EtherArp arpStorage;
        const EtherArp *arp;
        ArpKey *arpKey = &flow->arpKey;
        ((UINT64 *)arpKey)[0] = 0;
        ((UINT64 *)arpKey)[1] = 0;
        ((UINT64 *)arpKey)[2] = 0;
        flow->l2.keyLen += OVS_ARP_KEY_SIZE;
        arp = OvsGetArp(packet, layers->l3Offset, &arpStorage);
        if (arp && arp->ea_hdr.ar_hrd == htons(1) &&
            arp->ea_hdr.ar_pro == htons(ETH_TYPE_IPV4) &&
            arp->ea_hdr.ar_hln == ETH_ADDR_LENGTH &&
            arp->ea_hdr.ar_pln == 4) {
            /* We only match on the lower 8 bits of the opcode. */
            if (ntohs(arp->ea_hdr.ar_op) <= 0xff) {
                arpKey->nwProto = (UINT8)ntohs(arp->ea_hdr.ar_op);
            }
            if (arpKey->nwProto == ARPOP_REQUEST
                || arpKey->nwProto == ARPOP_REPLY) {
                memcpy(&arpKey->nwSrc, arp->arp_spa, 4);
                memcpy(&arpKey->nwDst, arp->arp_tpa, 4);
                memcpy(arpKey->arpSha, arp->arp_sha, ETH_ADDR_LENGTH);
                memcpy(arpKey->arpTha, arp->arp_tha, ETH_ADDR_LENGTH);
            }
        }
    }

    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsDoEncapVxlan
 *     Encapsulates the packet.
 *----------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsDoEncapVxlan(POVS_VPORT_ENTRY vport,
                PNET_BUFFER_LIST curNbl,
                OvsIPv4TunnelKey *tunKey,
                POVS_FWD_INFO fwdInfo,
                POVS_PACKET_HDR_INFO layers,
                POVS_SWITCH_CONTEXT switchContext,
                PNET_BUFFER_LIST *newNbl)
{
    NDIS_STATUS status;
    PNET_BUFFER curNb;
    PMDL curMdl;
    PUINT8 bufferStart;
    EthHdr *ethHdr;
    IPHdr *ipHdr;
    UDPHdr *udpHdr;
    VXLANHdr *vxlanHdr;
    POVS_VXLAN_VPORT vportVxlan;
    UINT32 headRoom = OvsGetVxlanTunHdrSize();
    UINT32 packetLength;
    vportVxlan = (POVS_VXLAN_VPORT)GetOvsVportPriv(vport);
    ASSERT(vportVxlan);

    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
    packetLength = NET_BUFFER_DATA_LENGTH(curNb);
    OvsExtractLayers(curNbl, layers);

    if (layers->isTcp) {
        NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO tsoInfo;

        tsoInfo.Value = NET_BUFFER_LIST_INFO(curNbl,
                                             TcpLargeSendNetBufferListInfo);
        OVS_LOG_TRACE("MSS %u packet len %u", tsoInfo.LsoV1Transmit.MSS, packetLength);
        switch (tsoInfo.Transmit.Type) {
        case NDIS_TCP_LARGE_SEND_OFFLOAD_V1_TYPE:
            if (tsoInfo.LsoV1Transmit.MSS) {
                OVS_LOG_TRACE("l4Offset %d", layers->l4Offset);
                *newNbl = OvsTcpSegmentNBL(switchContext, curNbl, layers,
                            tsoInfo.LsoV1Transmit.MSS, headRoom);
                if (*newNbl == NULL) {
                    OVS_LOG_ERROR("Unable to segment NBL");
                    return NDIS_STATUS_FAILURE;
                }
                NET_BUFFER_LIST_INFO(curNbl, TcpLargeSendNetBufferListInfo) = 0;
            }
            break;
        case NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE:
            if (tsoInfo.LsoV2Transmit.MSS) {
                OVS_LOG_TRACE("l4Offset %d", layers->l4Offset);
                *newNbl = OvsTcpSegmentNBL(switchContext, curNbl, layers,
                    tsoInfo.LsoV2Transmit.MSS, headRoom);
                if (*newNbl == NULL) {
                    OVS_LOG_ERROR("Unable to segment NBL");
                    return NDIS_STATUS_FAILURE;
                }
                NET_BUFFER_LIST_INFO(curNbl, TcpLargeSendNetBufferListInfo) = 0;
            }
            break;
        }
    }

    /* If we didn't split the packet above, make a copy now */
    if (*newNbl == NULL) {
        *newNbl = OvsPartialCopyNBL(switchContext, curNbl, 0, headRoom,
                                    FALSE /*NBL info*/);
        if (*newNbl == NULL) {
            OVS_LOG_ERROR("Unable to copy NBL");
            return NDIS_STATUS_FAILURE;
        }

        curNb = NET_BUFFER_LIST_FIRST_NB(*newNbl);
        curMdl = NET_BUFFER_CURRENT_MDL(curNb);
        bufferStart = (PUINT8)MmGetSystemAddressForMdlSafe(curMdl, LowPagePriority);
        bufferStart += NET_BUFFER_CURRENT_MDL_OFFSET(curNb);

        NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;
        csumInfo.Value = NET_BUFFER_LIST_INFO(curNbl,
                                              TcpIpChecksumNetBufferListInfo);

        if (layers->isIPv4) {
            IPHdr *ip = (IPHdr *)(bufferStart + layers->l3Offset);

            if (csumInfo.Transmit.IpHeaderChecksum) {
                ip->check = 0;
                ip->check = IPChecksum((UINT8 *)ip, 4 * ip->ihl, 0);
            }

            if (layers->isTcp && csumInfo.Transmit.TcpChecksum) {
                UINT16 csumLength = (UINT16)(packetLength - layers->l4Offset);
                TCPHdr *tcp = (TCPHdr *)(bufferStart + layers->l4Offset);
                tcp->check = IPPseudoChecksum(&ip->saddr, &ip->daddr,
                                              IPPROTO_TCP, csumLength);
                tcp->check = CalculateChecksumNB(curNb, csumLength,
                                                 (UINT32)(layers->l4Offset));
            }
            else if (layers->isUdp && csumInfo.Transmit.UdpChecksum) {
                UINT16 csumLength = (UINT16)(packetLength - layers->l4Offset);
                UDPHdr *udp = (UDPHdr *)((PCHAR)ip + sizeof *ip);
                udp->check = IPPseudoChecksum(&ip->saddr, &ip->daddr,
                                              IPPROTO_UDP, csumLength);
                udp->check = CalculateChecksumNB(curNb, csumLength,
                                                 (UINT32)(layers->l4Offset));
            }
        } else if (layers->isIPv6) {
            IPv6Hdr *ip = (IPv6Hdr *)(bufferStart + layers->l3Offset);

            if (layers->isTcp && csumInfo.Transmit.TcpChecksum) {
                UINT16 csumLength = (UINT16)(packetLength - layers->l4Offset);
                TCPHdr *tcp = (TCPHdr *)(bufferStart + layers->l4Offset);
                tcp->check = IPv6PseudoChecksum((UINT32 *) &ip->saddr,
                                                (UINT32 *) &ip->daddr,
                                                IPPROTO_TCP, csumLength);
                tcp->check = CalculateChecksumNB(curNb, csumLength,
                                                 (UINT32)(layers->l4Offset));
            }
            else if (layers->isUdp && csumInfo.Transmit.UdpChecksum) {
                UINT16 csumLength = (UINT16)(packetLength - layers->l4Offset);
                UDPHdr *udp = (UDPHdr *)((PCHAR)ip + sizeof *ip);
                udp->check = IPPseudoChecksum((UINT32 *) &ip->saddr,
                                              (UINT32 *)&ip->daddr,
                                              IPPROTO_UDP, csumLength);
                udp->check = CalculateChecksumNB(curNb, csumLength,
                                                 (UINT32)(layers->l4Offset));
            }
        }
    }

    curNbl = *newNbl;

    for (curNb = NET_BUFFER_LIST_FIRST_NB(curNbl); curNb != NULL;
            curNb = curNb->Next) {
        status = NdisRetreatNetBufferDataStart(curNb, headRoom, 0, NULL);
        if (status != NDIS_STATUS_SUCCESS) {
            goto ret_error;
        }

        curMdl = NET_BUFFER_CURRENT_MDL(curNb);
        bufferStart = (PUINT8)MmGetSystemAddressForMdlSafe(curMdl, LowPagePriority);
        if (!bufferStart) {
            status = NDIS_STATUS_RESOURCES;
            goto ret_error;
        }

        bufferStart += NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
        if (NET_BUFFER_NEXT_NB(curNb)) {
            OVS_LOG_TRACE("nb length %u next %u", NET_BUFFER_DATA_LENGTH(curNb),
                          NET_BUFFER_DATA_LENGTH(curNb->Next));
        }

        /* L2 header */
        ethHdr = (EthHdr *)bufferStart;
        ASSERT(((PCHAR)&fwdInfo->dstMacAddr + sizeof fwdInfo->dstMacAddr) ==
               (PCHAR)&fwdInfo->srcMacAddr);
        NdisMoveMemory(ethHdr->Destination, fwdInfo->dstMacAddr,
                       sizeof ethHdr->Destination + sizeof ethHdr->Source);
        ethHdr->Type = htons(ETH_TYPE_IPV4);

        /* IP header */
        ipHdr = (IPHdr *)((PCHAR)ethHdr + sizeof *ethHdr);

        ipHdr->ihl = sizeof *ipHdr / 4;
        ipHdr->version = IPPROTO_IPV4;
        ipHdr->tos = tunKey->tos;
        ipHdr->tot_len = htons(NET_BUFFER_DATA_LENGTH(curNb) - sizeof *ethHdr);
        ipHdr->id = (uint16)atomic_add64(&vportVxlan->ipId,
                                         NET_BUFFER_DATA_LENGTH(curNb));
        ipHdr->frag_off = (tunKey->flags & OVS_TNL_F_DONT_FRAGMENT) ?
                          IP_DF_NBO : 0;
        ipHdr->ttl = tunKey->ttl ? tunKey->ttl : VXLAN_DEFAULT_TTL;
        ipHdr->protocol = IPPROTO_UDP;
        ASSERT(tunKey->dst == fwdInfo->dstIpAddr);
        ASSERT(tunKey->src == fwdInfo->srcIpAddr || tunKey->src == 0);
        ipHdr->saddr = fwdInfo->srcIpAddr;
        ipHdr->daddr = fwdInfo->dstIpAddr;
        ipHdr->check = 0;
        ipHdr->check = IPChecksum((UINT8 *)ipHdr, sizeof *ipHdr, 0);

        /* UDP header */
        udpHdr = (UDPHdr *)((PCHAR)ipHdr + sizeof *ipHdr);
        udpHdr->source = htons(tunKey->flow_hash | MAXINT16);
        udpHdr->dest = htons(vportVxlan->dstPort);
        udpHdr->len = htons(NET_BUFFER_DATA_LENGTH(curNb) - headRoom +
                            sizeof *udpHdr + sizeof *vxlanHdr);
        udpHdr->check = 0;

        /* VXLAN header */
        vxlanHdr = (VXLANHdr *)((PCHAR)udpHdr + sizeof *udpHdr);
        vxlanHdr->flags1 = 0;
        vxlanHdr->locallyReplicate = 0;
        vxlanHdr->flags2 = 0;
        vxlanHdr->reserved1 = 0;
        if (tunKey->flags | OVS_TNL_F_KEY) {
            vxlanHdr->vxlanID = VXLAN_TUNNELID_TO_VNI(tunKey->tunnelId);
            vxlanHdr->instanceID = 1;
        }
        vxlanHdr->reserved2 = 0;
    }
    return STATUS_SUCCESS;

ret_error:
    OvsCompleteNBL(switchContext, *newNbl, TRUE);
    *newNbl = NULL;
    return status;
}


/*
 *----------------------------------------------------------------------------
 * OvsEncapVxlan --
 *     Encapsulates the packet if L2/L3 for destination resolves. Otherwise,
 *     enqueues a callback that does encapsulatation after resolution.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsEncapVxlan(POVS_VPORT_ENTRY vport,
              PNET_BUFFER_LIST curNbl,
              OvsIPv4TunnelKey *tunKey,
              POVS_SWITCH_CONTEXT switchContext,
              POVS_PACKET_HDR_INFO layers,
              PNET_BUFFER_LIST *newNbl)
{
    NTSTATUS status;
    OVS_FWD_INFO fwdInfo;

    status = OvsLookupIPFwdInfo(tunKey->dst, &fwdInfo);
    if (status != STATUS_SUCCESS) {
        OvsFwdIPHelperRequest(NULL, 0, tunKey, NULL, NULL, NULL);
        // return NDIS_STATUS_PENDING;
        /*
         * XXX: Don't know if the completionList will make any sense when
         * accessed in the callback. Make sure the caveats are known.
         *
         * XXX: This code will work once we are able to grab locks in the
         * callback.
         */
        return NDIS_STATUS_FAILURE;
    }

    return OvsDoEncapVxlan(vport, curNbl, tunKey, &fwdInfo, layers,
                           switchContext, newNbl);
}

/*
 *----------------------------------------------------------------------------
 * OvsCalculateUDPChecksum
 *     Calculate UDP checksum
 *----------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsCalculateUDPChecksum(PNET_BUFFER_LIST curNbl,
                        PNET_BUFFER curNb,
                        IPHdr *ipHdr,
                        UDPHdr *udpHdr,
                        UINT32 packetLength)
{
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;
    UINT16 checkSum;

    csumInfo.Value = NET_BUFFER_LIST_INFO(curNbl, TcpIpChecksumNetBufferListInfo);

    /* Next check if UDP checksum has been calculated. */
    if (!csumInfo.Receive.UdpChecksumSucceeded) {
        UINT32 l4Payload;

        checkSum = udpHdr->check;

        l4Payload = packetLength - sizeof(EthHdr) - ipHdr->ihl * 4;
        udpHdr->check = 0;
        udpHdr->check =
            IPPseudoChecksum((UINT32 *)&ipHdr->saddr,
                             (UINT32 *)&ipHdr->daddr,
                             IPPROTO_UDP, (UINT16)l4Payload);
        udpHdr->check = CalculateChecksumNB(curNb, (UINT16)l4Payload,
            sizeof(EthHdr) + ipHdr->ihl * 4);
        if (checkSum != udpHdr->check) {
            OVS_LOG_TRACE("UDP checksum incorrect.");
            return NDIS_STATUS_INVALID_PACKET;
        }
    }

    csumInfo.Receive.UdpChecksumSucceeded = 1;
    NET_BUFFER_LIST_INFO(curNbl, TcpIpChecksumNetBufferListInfo) = csumInfo.Value;
    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsDecapVxlan
 *     Decapsulates to tunnel header in 'curNbl' and puts into 'tunKey'.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsDecapVxlan(POVS_SWITCH_CONTEXT switchContext,
              PNET_BUFFER_LIST curNbl,
              OvsIPv4TunnelKey *tunKey,
              PNET_BUFFER_LIST *newNbl)
{
    PNET_BUFFER curNb;
    PMDL curMdl;
    EthHdr *ethHdr;
    IPHdr *ipHdr;
    UDPHdr *udpHdr;
    VXLANHdr *vxlanHdr;
    UINT32 tunnelSize = 0, packetLength = 0;
    PUINT8 bufferStart;
    NDIS_STATUS status;

    /* Check the the length of the UDP payload */
    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
    packetLength = NET_BUFFER_DATA_LENGTH(curNb);
    tunnelSize = OvsGetVxlanTunHdrSize();
    if (packetLength <= tunnelSize) {
        return NDIS_STATUS_INVALID_LENGTH;
    }

    /*
     * Create a copy of the NBL so that we have all the headers in one MDL.
     */
    *newNbl = OvsPartialCopyNBL(switchContext, curNbl,
                                tunnelSize + OVS_DEFAULT_COPY_SIZE, 0,
                                TRUE /*copy NBL info */);

    if (*newNbl == NULL) {
        return NDIS_STATUS_RESOURCES;
    }

    /* XXX: Handle VLAN header. */
    curNbl = *newNbl;
    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
    curMdl = NET_BUFFER_CURRENT_MDL(curNb);
    bufferStart = (PUINT8)MmGetSystemAddressForMdlSafe(curMdl, LowPagePriority) +
                  NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
    if (!bufferStart) {
        status = NDIS_STATUS_RESOURCES;
        goto dropNbl;
    }

    ethHdr = (EthHdr *)bufferStart;
    /* XXX: Handle IP options. */
    ipHdr = (IPHdr *)((PCHAR)ethHdr + sizeof *ethHdr);
    tunKey->src = ipHdr->saddr;
    tunKey->dst = ipHdr->daddr;
    tunKey->tos = ipHdr->tos;
    tunKey->ttl = ipHdr->ttl;
    tunKey->pad = 0;
    udpHdr = (UDPHdr *)((PCHAR)ipHdr + sizeof *ipHdr);

    /* Validate if NIC has indicated checksum failure. */
    status = OvsValidateUDPChecksum(curNbl, udpHdr->check == 0);
    if (status != NDIS_STATUS_SUCCESS) {
        goto dropNbl;
    }

    /* Calculate and verify UDP checksum if NIC didn't do it. */
    if (udpHdr->check != 0) {
        status = OvsCalculateUDPChecksum(curNbl, curNb, ipHdr, udpHdr, packetLength);
        if (status != NDIS_STATUS_SUCCESS) {
            goto dropNbl;
        }
    }

    vxlanHdr = (VXLANHdr *)((PCHAR)udpHdr + sizeof *udpHdr);
    if (vxlanHdr->instanceID) {
        tunKey->flags = OVS_TNL_F_KEY;
        tunKey->tunnelId = VXLAN_VNI_TO_TUNNELID(vxlanHdr->vxlanID);
    } else {
        tunKey->flags = 0;
        tunKey->tunnelId = 0;
    }

    /* Clear out the receive flag for the inner packet. */
    NET_BUFFER_LIST_INFO(curNbl, TcpIpChecksumNetBufferListInfo) = 0;
    NdisAdvanceNetBufferDataStart(curNb, tunnelSize, FALSE, NULL);
    return NDIS_STATUS_SUCCESS;

dropNbl:
    OvsCompleteNBL(switchContext, *newNbl, TRUE);
    *newNbl = NULL;
    return status;
}


NDIS_STATUS
OvsSlowPathDecapVxlan(const PNET_BUFFER_LIST packet,
                   OvsIPv4TunnelKey *tunnelKey)
{
    NDIS_STATUS status = NDIS_STATUS_FAILURE;
    UDPHdr udpStorage;
    const UDPHdr *udp;
    VXLANHdr *VxlanHeader;
    VXLANHdr  VxlanHeaderBuffer;
    struct IPHdr ip_storage;
    const struct IPHdr *nh;
    OVS_PACKET_HDR_INFO layers;

    layers.value = 0;

    do {
        nh = OvsGetIp(packet, layers.l3Offset, &ip_storage);
        if (nh) {
            layers.l4Offset = layers.l3Offset + nh->ihl * 4;
        } else {
            break;
        }

        /* make sure it's a VXLAN packet */
        udp = OvsGetUdp(packet, layers.l4Offset, &udpStorage);
        if (udp) {
            layers.l7Offset = layers.l4Offset + sizeof *udp;
        } else {
            break;
        }

        VxlanHeader = (VXLANHdr *)OvsGetPacketBytes(packet,
                                                    sizeof(*VxlanHeader),
                                                    layers.l7Offset,
                                                    &VxlanHeaderBuffer);

        if (VxlanHeader) {
            tunnelKey->src = nh->saddr;
            tunnelKey->dst = nh->daddr;
            tunnelKey->ttl = nh->ttl;
            tunnelKey->tos = nh->tos;
            if (VxlanHeader->instanceID) {
                tunnelKey->flags = OVS_TNL_F_KEY;
                tunnelKey->tunnelId = VXLAN_VNI_TO_TUNNELID(VxlanHeader->vxlanID);
            } else {
                tunnelKey->flags = 0;
                tunnelKey->tunnelId = 0;
            }
        } else {
            break;
        }
        status = NDIS_STATUS_SUCCESS;

    } while(FALSE);

    return status;
}

#pragma warning( pop )
