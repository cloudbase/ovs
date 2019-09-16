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

#ifndef RTWIN_H
#define RTWIN_H 1

#include "openvswitch/list.h"

/*
 * Function called to report that a netdev has changed.
 * 'aux' is as specified in the call to *rtwin_notifier_register().
 */
typedef void rtwin_notify_func(void *aux);

struct rtwin_notifier {
    struct ovs_list node;
    rtwin_notify_func *cb;
    void *aux;
};

int rtwin_notifier_register(struct rtwin_notifier *,
                                rtwin_notify_func *, void *aux);
void rtwin_notifier_unregister(struct rtwin_notifier *);
void rtwin_notifier_run(void);
void rtwin_notifier_wait(void);

#endif /* rtwin.h */
