/*
 * Copyright (C) 2014 The Android Open Source Project
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

package android.os;


/** @hide */
interface IDebuggingManager
{
    /* Enable or disable debugging using adb */
    void setAdbEnabled(boolean enabled);

    /* Allow debugging from the attached host. If alwaysAllow is true, add the
     * the public key to list of host keys that the user has approved.
     */
    void allowDebugging(boolean alwaysAllow, String publicKey);

    /* Deny debugging from the attached host */
    void denyDebugging();

    /* Clear public keys installed for secure ADB debugging */
    void clearDebuggingKeys();
}
