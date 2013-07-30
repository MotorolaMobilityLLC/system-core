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

//
#ifndef ANDROID_IINTERFACE_H
#define ANDROID_IINTERFACE_H

#include <utils/Binder.h>

namespace android {

// ----------------------------------------------------------------------

class IInterface : public virtual RefBase
{
public:
            sp<IBinder>         asBinder();
            sp<const IBinder>   asBinder() const;

protected:
    virtual IBinder*            onAsBinder() = 0;
};

// ----------------------------------------------------------------------

template<typename INTERFACE>
inline sp<INTERFACE> interface_cast(const sp<IBinder>& obj)
{
    return INTERFACE::asInterface(obj);
}

// ----------------------------------------------------------------------

template<typename INTERFACE>
class BnInterface : public INTERFACE, public BBinder
{
public:
    virtual sp<IInterface>      queryLocalInterface(const String16& _descriptor);
    virtual String16            getInterfaceDescriptor() const;

protected:
    virtual IBinder*            onAsBinder();
};

// ----------------------------------------------------------------------

template<typename INTERFACE>
class BpInterface : public INTERFACE, public BpRefBase
{
public:
                                BpInterface(const sp<IBinder>& remote);

protected:
    virtual IBinder*            onAsBinder();
};

// ----------------------------------------------------------------------

#define DECLARE_META_INTERFACE(INTERFACE)                               \
    static const String16 descriptor;                                   \
    static sp<I##INTERFACE> asInterface(const sp<IBinder>& obj);        \
    virtual String16 getInterfaceDescriptor() const;                    \

#define IMPLEMENT_META_INTERFACE(INTERFACE, NAME)                       \
    const String16 I##INTERFACE::descriptor(NAME);                      \
    String16 I##INTERFACE::getInterfaceDescriptor() const {             \
        return I##INTERFACE::descriptor;                                \
    }                                                                   \
    sp<I##INTERFACE> I##INTERFACE::asInterface(const sp<IBinder>& obj)  \
    {                                                                   \
        sp<I##INTERFACE> intr;                                          \
        if (obj != NULL) {                                              \
            intr = static_cast<I##INTERFACE*>(                          \
                obj->queryLocalInterface(                               \
                        I##INTERFACE::descriptor).get());               \
            if (intr == NULL) {                                         \
                intr = new Bp##INTERFACE(obj);                          \
            }                                                           \
        }                                                               \
        return intr;                                                    \
    }                                                                   \

// ----------------------------------------------------------------------
// No user-servicable parts after this...

template<typename INTERFACE>
inline sp<IInterface> BnInterface<INTERFACE>::queryLocalInterface(
        const String16& _descriptor)
{
    if (_descriptor == INTERFACE::descriptor) return this;
    return NULL;
}

template<typename INTERFACE>
inline String16 BnInterface<INTERFACE>::getInterfaceDescriptor() const
{
    return INTERFACE::getInterfaceDescriptor();
}

template<typename INTERFACE>
IBinder* BnInterface<INTERFACE>::onAsBinder()
{
    return this;
}

template<typename INTERFACE>
inline BpInterface<INTERFACE>::BpInterface(const sp<IBinder>& remote)
    : BpRefBase(remote)
{
}

template<typename INTERFACE>
inline IBinder* BpInterface<INTERFACE>::onAsBinder()
{
    return remote();
}
    
// ----------------------------------------------------------------------

}; // namespace android

#endif // ANDROID_IINTERFACE_H
