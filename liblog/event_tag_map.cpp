/*
 * Copyright (C) 2007-2016 The Android Open Source Project
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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <experimental/string_view>
#include <functional>
#include <unordered_map>

#include <log/event_tag_map.h>

#include "log_portability.h"

#define OUT_TAG "EventTagMap"

typedef std::experimental::string_view MapString;

typedef std::pair<MapString, MapString> TagFmt;

template <> struct std::hash<TagFmt>
        : public std::unary_function<const TagFmt&, size_t> {
    size_t operator()(const TagFmt& __t) const noexcept {
        // Tag is typically unique.  Will cost us an extra 100ns for the
        // unordered_map lookup if we instead did a hash that combined
        // both of tag and fmt members, e.g.:
        //
        // return std::hash<MapString>()(__t.first) ^
        //        std::hash<MapString>()(__t.second);
        return std::hash<MapString>()(__t.first);
    }
};

// Map
struct EventTagMap {
#   define NUM_MAPS 2
    // memory-mapped source file; we get strings from here
    void*  mapAddr[NUM_MAPS];
    size_t mapLen[NUM_MAPS];

private:
    std::unordered_map<uint32_t, TagFmt> Idx2TagFmt;

public:
    EventTagMap() {
        memset(mapAddr, 0, sizeof(mapAddr));
        memset(mapLen, 0, sizeof(mapLen));
    }

    ~EventTagMap() {
        Idx2TagFmt.clear();
        for (size_t which = 0; which < NUM_MAPS; ++which) {
            if (mapAddr[which]) {
                munmap(mapAddr[which], mapLen[which]);
                mapAddr[which] = 0;
            }
        }
    }

    bool emplaceUnique(uint32_t tag, const TagFmt& tagfmt, bool verbose = false);
    const TagFmt* find(uint32_t tag) const;
};

bool EventTagMap::emplaceUnique(uint32_t tag, const TagFmt& tagfmt, bool verbose) {
    std::unordered_map<uint32_t, TagFmt>::const_iterator it;
    it = Idx2TagFmt.find(tag);
    if (it != Idx2TagFmt.end()) {
        if (verbose) {
            fprintf(stderr,
                    OUT_TAG ": duplicate tag entries %" PRIu32
                        ":%.*s:%.*s and %" PRIu32 ":%.*s:%.*s)\n",
                    it->first,
                    (int)it->second.first.length(), it->second.first.data(),
                    (int)it->second.second.length(), it->second.second.data(),
                    tag,
                    (int)tagfmt.first.length(), tagfmt.first.data(),
                    (int)tagfmt.second.length(), tagfmt.second.data());
        }
        return false;
    }

    Idx2TagFmt.emplace(std::make_pair(tag, tagfmt));
    return true;
}

const TagFmt* EventTagMap::find(uint32_t tag) const {
    std::unordered_map<uint32_t, TagFmt>::const_iterator it;
    it = Idx2TagFmt.find(tag);
    if (it == Idx2TagFmt.end()) return NULL;
    return &(it->second);
}

// Scan one tag line.
//
// "*pData" should be pointing to the first digit in the tag number.  On
// successful return, it will be pointing to the last character in the
// tag line (i.e. the character before the start of the next line).
//
// Returns 0 on success, nonzero on failure.
static int scanTagLine(EventTagMap* map, char** pData, int lineNum) {
    char* cp;
    unsigned long val = strtoul(*pData, &cp, 10);
    if (cp == *pData) {
        fprintf(stderr, OUT_TAG ": malformed tag number on line %d\n", lineNum);
        errno = EINVAL;
        return -1;
    }

    uint32_t tagIndex = val;
    if (tagIndex != val) {
        fprintf(stderr, OUT_TAG ": tag number too large on line %d\n", lineNum);
        errno = ERANGE;
        return -1;
    }

    while ((*++cp != '\n') && isspace(*cp)) {
    }

    if (*cp == '\n') {
        fprintf(stderr, OUT_TAG ": missing tag string on line %d\n", lineNum);
        errno = EINVAL;
        return -1;
    }

    const char* tag = cp;
    // Determine whether "c" is a valid tag char.
    while (isalnum(*++cp) || (*cp == '_')) { }
    size_t tagLen = cp - tag;

    if (!isspace(*cp)) {
        fprintf(stderr, OUT_TAG ": invalid tag chars on line %d\n", lineNum);
        errno = EINVAL;
        return -1;
    }

    while (isspace(*cp) && (*cp != '\n')) ++cp;
    const char* fmt = NULL;
    size_t fmtLen = 0;
    if (*cp != '#') {
        fmt = cp;
        while ((*cp != '\n') && (*cp != '#')) ++cp;
        while ((cp > fmt) && isspace(*(cp - 1))) --cp;
        fmtLen = cp - fmt;
    }

    // KISS Only report identicals if they are global
    // Ideally we want to check if there are identicals
    // recorded for the same uid, but recording that
    // unused detail in our database is too burdensome.
    bool verbose = true;
    while ((*cp != '#') && (*cp != '\n')) ++cp;
    if (*cp == '#') {
        do {
            ++cp;
        } while (isspace(*cp) && (*cp != '\n'));
        verbose = !!fastcmp<strncmp>(cp, "uid=", strlen("uid="));
    }

    while (*cp != '\n') ++cp;
#ifdef DEBUG
    fprintf(stderr, "%d: %p: %.*s\n", lineNum, tag, (int)(cp - *pData), *pData);
#endif
    *pData = cp;

    if (map->emplaceUnique(tagIndex, TagFmt(std::make_pair(
            MapString(tag, tagLen), MapString(fmt, fmtLen))), verbose)) {
        return 0;
    }
    errno = EMLINK;
    return -1;
}

static const char* eventTagFiles[NUM_MAPS] = {
    EVENT_TAG_MAP_FILE,
    "/dev/event-log-tags",
};

// Parse the tags out of the file.
static int parseMapLines(EventTagMap* map, size_t which) {
    char* cp = static_cast<char*>(map->mapAddr[which]);
    size_t len = map->mapLen[which];
    char* endp = cp + len;

    // insist on EOL at EOF; simplifies parsing and null-termination
    if (!len || (*(endp - 1) != '\n')) {
#ifdef DEBUG
        fprintf(stderr, OUT_TAG ": map file %zu[%zu] missing EOL on last line\n",
                which, len);
#endif
        if (which) { // do not propagate errors for other files
            return 0;
        }
        errno = EINVAL;
        return -1;
    }

    bool lineStart = true;
    int lineNum = 1;
    while (cp < endp) {
        if (*cp == '\n') {
            lineStart = true;
            lineNum++;
        } else if (lineStart) {
            if (*cp == '#') {
                // comment; just scan to end
                lineStart = false;
            } else if (isdigit(*cp)) {
                // looks like a tag; scan it out
                if (scanTagLine(map, &cp, lineNum) != 0) {
                    if (!which || (errno != EMLINK)) {
                        return -1;
                    }
                }
                lineNum++;      // we eat the '\n'
                // leave lineStart==true
            } else if (isspace(*cp)) {
                // looks like leading whitespace; keep scanning
            } else {
                fprintf(stderr,
                        OUT_TAG ": unexpected chars (0x%02x) in tag number on line %d\n",
                        *cp, lineNum);
                errno = EINVAL;
                return -1;
            }
        } else {
            // this is a blank or comment line
        }
        cp++;
    }

    return 0;
}

// Open the map file and allocate a structure to manage it.
//
// We create a private mapping because we want to terminate the log tag
// strings with '\0'.
LIBLOG_ABI_PUBLIC EventTagMap* android_openEventTagMap(const char* fileName) {
    EventTagMap* newTagMap;
    off_t end[NUM_MAPS];
    int save_errno, fd[NUM_MAPS];
    size_t which;

    memset(fd, -1, sizeof(fd));
    memset(end, 0, sizeof(end));

    for (which = 0; which < NUM_MAPS; ++which) {
        const char* tagfile = fileName ? fileName : eventTagFiles[which];

        fd[which] = open(tagfile, O_RDONLY | O_CLOEXEC);
        if (fd[which] < 0) {
            if (!which) {
                save_errno = errno;
                fprintf(stderr, OUT_TAG ": unable to open map '%s': %s\n",
                        tagfile, strerror(save_errno));
                goto fail_errno;
            }
            continue;
        }
        end[which] = lseek(fd[which], 0L, SEEK_END);
        save_errno = errno;
        (void)lseek(fd[which], 0L, SEEK_SET);
        if (!which && (end[0] < 0)) {
            fprintf(stderr, OUT_TAG ": unable to seek map '%s' %s\n",
                    tagfile, strerror(save_errno));
            goto fail_close;
        }
        if (fileName) break; // Only allow one as specified
    }

    newTagMap = new EventTagMap;
    if (newTagMap == NULL) {
        save_errno = errno;
        goto fail_close;
    }

    for (which = 0; which < NUM_MAPS; ++which) {
        if (fd[which] >= 0) {
            newTagMap->mapAddr[which] = mmap(NULL, end[which],
                                             which ?
                                                 PROT_READ :
                                                 PROT_READ | PROT_WRITE,
                                             which ?
                                                 MAP_SHARED :
                                                 MAP_PRIVATE,
                                             fd[which], 0);
            save_errno = errno;
            close(fd[which]);
            fd[which] = -1;
            if ((newTagMap->mapAddr[which] != MAP_FAILED) &&
                (newTagMap->mapAddr[which] != NULL)) {
                newTagMap->mapLen[which] = end[which];
            } else if (!which) {
                const char* tagfile = fileName ? fileName : eventTagFiles[which];

                fprintf(stderr, OUT_TAG ": mmap(%s) failed: %s\n",
                        tagfile, strerror(save_errno));
                goto fail_unmap;
            }
        }
    }

    for (which = 0; which < NUM_MAPS; ++which) {
        if (parseMapLines(newTagMap, which) != 0) {
            delete newTagMap;
            return NULL;
        }
    }

    return newTagMap;

fail_unmap:
    save_errno = EINVAL;
    delete newTagMap;
fail_close:
    for (which = 0; which < NUM_MAPS; ++which) close(fd[which]);
fail_errno:
    errno = save_errno;
    return NULL;
}

// Close the map.
LIBLOG_ABI_PUBLIC void android_closeEventTagMap(EventTagMap* map) {
    if (map) delete map;
}

// Look up an entry in the map.
LIBLOG_ABI_PUBLIC const char* android_lookupEventTag_len(const EventTagMap* map,
                                                         size_t *len,
                                                         unsigned int tag) {
    if (len) *len = 0;
    const TagFmt* str = map->find(tag);
    if (!str) return NULL;
    if (len) *len = str->first.length();
    return str->first.data();
}

// Look up an entry in the map.
LIBLOG_ABI_PUBLIC const char* android_lookupEventFormat_len(
        const EventTagMap* map, size_t *len, unsigned int tag) {
    if (len) *len = 0;
    const TagFmt* str = map->find(tag);
    if (!str) return NULL;
    if (len) *len = str->second.length();
    return str->second.data();
}

// This function is deprecated and replaced with android_lookupEventTag_len
// since it will cause the map to change from Shared and backed by a file,
// to Private Dirty and backed up by swap, albeit highly compressible. By
// deprecating this function everywhere, we save 100s of MB of memory space.
LIBLOG_ABI_PUBLIC const char* android_lookupEventTag(const EventTagMap* map,
                                                     unsigned int tag) {
    size_t len;
    const char* tagStr = android_lookupEventTag_len(map, &len, tag);

    if (!tagStr) return tagStr;
    char* cp = const_cast<char*>(tagStr);
    cp += len;
    if (*cp) *cp = '\0'; // Trigger copy on write :-( and why deprecated.
    return tagStr;
}
