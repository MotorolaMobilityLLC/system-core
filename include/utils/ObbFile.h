/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef OBBFILE_H_
#define OBBFILE_H_

#include <stdint.h>

#include <utils/RefBase.h>
#include <utils/String8.h>

namespace android {

class ObbFile : public RefBase {
protected:
    virtual ~ObbFile();

public:
    ObbFile();

    bool readFrom(const char* filename);
    bool readFrom(int fd);
    bool writeTo(const char* filename);
    bool writeTo(int fd);
    bool removeFrom(const char* filename);
    bool removeFrom(int fd);

    const char* getFileName() const {
        return mFileName;
    }

    const String8 getPackageName() const {
        return mPackageName;
    }

    int32_t getVersion() const {
        return mVersion;
    }

    void setPackageName(String8 packageName) {
        mPackageName = packageName;
    }

    void setVersion(int32_t version) {
        mVersion = version;
    }

    static inline uint32_t get4LE(const unsigned char* buf) {
        return buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
    }

    static inline void put4LE(unsigned char* buf, uint32_t val) {
        buf[0] = val & 0xFF;
        buf[1] = (val >> 8) & 0xFF;
        buf[2] = (val >> 16) & 0xFF;
        buf[3] = (val >> 24) & 0xFF;
    }

private:
    /* Package name this ObbFile is associated with */
    String8 mPackageName;

    /* Package version this ObbFile is associated with */
    int32_t mVersion;

    const char* mFileName;

    size_t mFileSize;

    size_t mFooterStart;

    unsigned char* mReadBuf;

    bool parseObbFile(int fd);
};

}
#endif /* OBBFILE_H_ */
