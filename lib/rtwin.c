/*
 * Copyright (c) 2019 Cloudbase Solutions Srl
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

#include <config.h>
#include "rtwin.h"
#include "coverage.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(rtwin);
COVERAGE_DEFINE(rtwin_changed);

static struct ovs_mutex rtwin_mutex = OVS_MUTEX_INITIALIZER;

/* HANDLE which will be used to wait for the device notification events. */
HANDLE notify_sock = NULL;

/* All registered notifiers. */
static struct ovs_list all_notifiers = OVS_LIST_INITIALIZER(&all_notifiers);

/* Registers 'cb' to be called with auxiliary data 'aux' with network device
 * change notifications.  The notifier is stored in 'notifier', which the
 * caller must not modify or free.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
rtwin_notifier_register(struct rtwin_notifier *notifier,
                            rtwin_notify_func *cb, void *aux)
    OVS_EXCLUDED(rtwin_mutex)
{
    int error = 0;

    ovs_mutex_lock(&rtwin_mutex);
    if (notify_sock == NULL) {
        notify_sock = CreateEvent(NULL, TRUE, FALSE, "interface_changed");
        if (notify_sock == NULL) {
            VLOG_WARN("could not create PF_ROUTE socket: %s",
                      ovs_strerror(errno));
            error = errno;
            goto out;
        }
    }

    ovs_list_push_back(&all_notifiers, &notifier->node);
    notifier->cb = cb;
    notifier->aux = aux;

out:
    ovs_mutex_unlock(&rtwin_mutex);
    return error;
}

/* Cancels notification on 'notifier', which must have previously been
 * registered with rtwin_notifier_register(). */
void
rtwin_notifier_unregister(struct rtwin_notifier *notifier)
    OVS_EXCLUDED(rtwin_mutex)
{
    ovs_mutex_lock(&rtwin_mutex);
    ovs_list_remove(&notifier->node);
    if (ovs_list_is_empty(&all_notifiers)) {
        CloseHandle(notify_sock);
        notify_sock = NULL;
    }
    ovs_mutex_unlock(&rtwin_mutex);
}

/* Calls all of the registered notifiers, passing along any as-yet-unreported
 * netdev change events. */
void
rtwin_notifier_run(void)
    OVS_EXCLUDED(rtwin_mutex)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    ovs_mutex_lock(&rtwin_mutex);
    if (notify_sock == NULL) {
        ovs_mutex_unlock(&rtwin_mutex);
        return;
    }
    DWORD val = WaitForSingleObjectEx(notify_sock, 0, FALSE);
    if (val == WAIT_OBJECT_0) {
        struct rtwin_notifier *notifier;
        ResetEvent(notify_sock);
        LIST_FOR_EACH (notifier, node, &all_notifiers) {
            notifier->cb(notifier->aux);
        }
    }
    ovs_mutex_unlock(&rtwin_mutex);
}

/* Causes poll_block() to wake up when network device change notifications are
 * ready. */
void
rtwin_notifier_wait(void)
    OVS_EXCLUDED(rtwin_mutex)
{
    ovs_mutex_lock(&rtwin_mutex);
    if (notify_sock != NULL) {
        poll_wevent_wait(notify_sock);
    }
    ovs_mutex_unlock(&rtwin_mutex);
}
