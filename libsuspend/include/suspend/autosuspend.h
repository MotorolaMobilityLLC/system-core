/*
* Copyright (C) 2014 MediaTek Inc.
* Modification based on code covered by the mentioned copyright
* and/or permission notice(s).
*/
/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _LIBSUSPEND_AUTOSUSPEND_H_
#define _LIBSUSPEND_AUTOSUSPEND_H_

#include <sys/cdefs.h>
#include <stdbool.h>

__BEGIN_DECLS

/*
 * autosuspend_enable
 *
 * Turn on autosuspend in the kernel, allowing it to enter suspend if no
 * wakelocks/wakeup_sources are held.
 *
 *
 *
 * Returns 0 on success, -1 if autosuspend was not enabled.
 */
int autosuspend_enable(void);

/*
 * autosuspend_disable
 *
 * Turn off autosuspend in the kernel, preventing suspend and synchronizing
 * with any in-progress resume.
 *
 * Returns 0 on success, -1 if autosuspend was not disabled.
 */
int autosuspend_disable(void);

/*
 * set_wakeup_callback
 *
 * Set a function to be called each time the device returns from suspend.
 * success is true if the suspend was sucessful and false if the suspend
 * aborted due to some reason.
 */
void set_wakeup_callback(void (*func)(bool success));

__END_DECLS

#endif
