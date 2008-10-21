/*
 * Copyright (C) 2005 The Android Open Source Project
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

#ifndef ANDROID_IPC_THREAD_STATE_H
#define ANDROID_IPC_THREAD_STATE_H

#include <utils/Errors.h>
#include <utils/Parcel.h>
#include <utils/ProcessState.h>

#ifdef HAVE_WIN32_PROC
typedef  int  uid_t;
#endif

// ---------------------------------------------------------------------------
namespace android {

class IPCThreadState
{
public:
    static  IPCThreadState*     self();
    
            sp<ProcessState>    process();
            
            status_t            clearLastError();

            int                 getCallingPid();
            int                 getCallingUid();
            
            int64_t             clearCallingIdentity();
            void                restoreCallingIdentity(int64_t token);
            
            void                flushCommands();

            void                joinThreadPool(bool isMain = true);
            
            // Stop the local process.
            void                stopProcess(bool immediate = true);
            
            status_t            transact(int32_t handle,
                                         uint32_t code, const Parcel& data,
                                         Parcel* reply, uint32_t flags);

            void                incStrongHandle(int32_t handle);
            void                decStrongHandle(int32_t handle);
            void                incWeakHandle(int32_t handle);
            void                decWeakHandle(int32_t handle);
            status_t            attemptIncStrongHandle(int32_t handle);
    static  void                expungeHandle(int32_t handle, IBinder* binder);
            status_t            requestDeathNotification(   int32_t handle,
                                                            BpBinder* proxy); 
            status_t            clearDeathNotification( int32_t handle,
                                                        BpBinder* proxy); 

    static  void                shutdown();
    
private:
                                IPCThreadState();
                                ~IPCThreadState();

            status_t            sendReply(const Parcel& reply, uint32_t flags);
            status_t            waitForResponse(Parcel *reply,
                                                status_t *acquireResult=NULL);
            status_t            talkWithDriver(bool doReceive=true);
            status_t            writeTransactionData(int32_t cmd,
                                                     uint32_t binderFlags,
                                                     int32_t handle,
                                                     uint32_t code,
                                                     const Parcel& data,
                                                     status_t* statusBuffer);
            status_t            executeCommand(int32_t command);
            
            void                clearCaller();
            
    static  void                threadDestructor(void *st);
    static  void                freeBuffer(Parcel* parcel,
                                           const uint8_t* data, size_t dataSize,
                                           const size_t* objects, size_t objectsSize,
                                           void* cookie);
    
    const   sp<ProcessState>    mProcess;
                                
            Parcel              mIn;
            Parcel              mOut;
            status_t            mLastError;
            pid_t               mCallingPid;
            uid_t               mCallingUid;
};
    
}; // namespace android

// ---------------------------------------------------------------------------

#endif // ANDROID_IPC_THREAD_STATE_H
