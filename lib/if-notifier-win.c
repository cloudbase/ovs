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
#include <stddef.h>
#include "if-notifier.h"
#include "rtwin.h"
#include "compiler.h"
#include "util.h"

struct if_notifier {
    struct rtwin_notifier notifier;
    if_notify_func *cb;
    void *aux;
};

static void
if_notifier_cb(void *aux)
{
    struct if_notifier *notifier;
    notifier = aux;
    notifier->cb(notifier->aux);
}

struct if_notifier *
if_notifier_create(if_notify_func *cb OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct if_notifier *notifier;
    int ret;
    notifier = xzalloc(sizeof *notifier);
    notifier->cb = cb;
    notifier->aux = aux;
    ret = rtwin_notifier_register(&notifier->notifier, if_notifier_cb,
                                  notifier);
    if (ret) {
        free(notifier);
        return NULL;
    }
    return notifier;
}

void
if_notifier_destroy(struct if_notifier *notifier OVS_UNUSED)
{
    if (notifier) {
        rtwin_notifier_unregister(&notifier->notifier);
        free(notifier);
    }
}

void
if_notifier_run(void)
{
    rtwin_notifier_run();
}

void
if_notifier_wait(void)
{
    rtwin_notifier_wait();
}
