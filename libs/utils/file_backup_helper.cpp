#define LOG_TAG "file_backup_helper"

#include <utils/backup_helpers.h>

#include <utils/KeyedVector.h>
#include <utils/ByteOrder.h>
#include <utils/String8.h>

#include <errno.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <zlib.h>

#include <cutils/log.h>

using namespace android;

#define MAGIC0 0x70616e53 // Snap
#define MAGIC1 0x656c6946 // File

struct SnapshotHeader {
    int magic0;
    int fileCount;
    int magic1;
    int totalSize;
};

struct FileState {
    int modTime_sec;
    int modTime_nsec;
    int size;
    int crc32;
    int nameLen;
};

const static int ROUND_UP[4] = { 0, 3, 2, 1 };

static inline int
round_up(int n)
{
    return n + ROUND_UP[n % 4];
}

static int
read_snapshot_file(int fd, KeyedVector<String8,FileState>* snapshot)
{
    int bytesRead = 0;
    int amt;
    SnapshotHeader header;

    amt = read(fd, &header, sizeof(header));
    if (amt != sizeof(header)) {
        return errno;
    }
    bytesRead += amt;

    if (header.magic0 != MAGIC0 || header.magic1 != MAGIC1) {
        LOGW("read_snapshot_file header.magic0=0x%08x magic1=0x%08x", header.magic0, header.magic1);
        return 1;
    }

    for (int i=0; i<header.fileCount; i++) {
        FileState file;
        char filenameBuf[128];

        amt = read(fd, &file, sizeof(file));
        if (amt != sizeof(file)) {
            LOGW("read_snapshot_file FileState truncated/error with read at %d bytes\n", bytesRead);
            return 1;
        }
        bytesRead += amt;

        // filename is not NULL terminated, but it is padded
        int nameBufSize = round_up(file.nameLen);
        char* filename = nameBufSize <= (int)sizeof(filenameBuf)
                ? filenameBuf
                : (char*)malloc(nameBufSize);
        amt = read(fd, filename, nameBufSize);
        if (amt == nameBufSize) {
            snapshot->add(String8(filename, file.nameLen), file);
        }
        bytesRead += amt;
        if (filename != filenameBuf) {
            free(filename);
        }
        if (amt != nameBufSize) {
            LOGW("read_snapshot_file filename truncated/error with read at %d bytes\n", bytesRead);
            return 1;
        }
    }

    if (header.totalSize != bytesRead) {
        LOGW("read_snapshot_file length mismatch: header.totalSize=%d bytesRead=%d\n",
                header.totalSize, bytesRead);
        return 1;
    }

    return 0;
}

static int
write_snapshot_file(int fd, const KeyedVector<String8,FileState>& snapshot)
{
    int bytesWritten = sizeof(SnapshotHeader);
    // preflight size
    const int N = snapshot.size();
    for (int i=0; i<N; i++) {
        const String8& name = snapshot.keyAt(i);
        bytesWritten += sizeof(FileState) + round_up(name.length());
    }

    int amt;
    SnapshotHeader header = { MAGIC0, N, MAGIC1, bytesWritten };

    amt = write(fd, &header, sizeof(header));
    if (amt != sizeof(header)) {
        LOGW("write_snapshot_file error writing header %s", strerror(errno));
        return errno;
    }

    for (int i=0; i<header.fileCount; i++) {
        const String8& name = snapshot.keyAt(i);
        FileState file = snapshot.valueAt(i);
        int nameLen = file.nameLen = name.length();

        amt = write(fd, &file, sizeof(file));
        if (amt != sizeof(file)) {
            LOGW("write_snapshot_file error writing header %s", strerror(errno));
            return 1;
        }

        // filename is not NULL terminated, but it is padded
        amt = write(fd, name.string(), nameLen);
        if (amt != nameLen) {
            LOGW("write_snapshot_file error writing filename %s", strerror(errno));
            return 1;
        }
        int paddingLen = ROUND_UP[nameLen % 4];
        if (paddingLen != 0) {
            int padding = 0xabababab;
            amt = write(fd, &padding, paddingLen);
            if (amt != paddingLen) {
                LOGW("write_snapshot_file error writing %d bytes of filename padding %s",
                        paddingLen, strerror(errno));
                return 1;
            }
        }
    }

    return 0;
}

static int
write_delete_file(const String8& key)
{
    printf("write_delete_file %s\n", key.string());
    return 0;
}

static int
write_update_file(const String8& realFilename, const String8& key)
{
    printf("write_update_file %s (%s)\n", realFilename.string(), key.string());
    return 0;
}

static int
compute_crc32(const String8& filename)
{
    const int bufsize = 4*1024;
    int amt;

    int fd = open(filename.string(), O_RDONLY);
    if (fd == -1) {
        return -1;
    }

    char* buf = (char*)malloc(bufsize);
    int crc = crc32(0L, Z_NULL, 0);

    while ((amt = read(fd, buf, bufsize)) != 0) {
        crc = crc32(crc, (Bytef*)buf, amt);
    }

    close(fd);
    free(buf);

    return crc;
}

int
back_up_files(int oldSnapshotFD, int newSnapshotFD, int oldDataStream,
        char const* fileBase, char const* const* files, int fileCount)
{
    int err;
    const String8 base(fileBase);
    KeyedVector<String8,FileState> oldSnapshot;
    KeyedVector<String8,FileState> newSnapshot;

    if (oldSnapshotFD != -1) {
        err = read_snapshot_file(oldSnapshotFD, &oldSnapshot);
        if (err != 0) {
            // On an error, treat this as a full backup.
            oldSnapshot.clear();
        }
    }

    for (int i=0; i<fileCount; i++) {
        String8 name(files[i]);
        FileState s;
        struct stat st;
        String8 realFilename(base);
        realFilename.appendPath(name);

        err = stat(realFilename.string(), &st);
        if (err != 0) {
            LOGW("Error stating file %s", realFilename.string());
            continue;
        }

        s.modTime_sec = st.st_mtime;
        s.modTime_nsec = st.st_mtime_nsec;
        s.size = st.st_size;
        s.crc32 = compute_crc32(realFilename);

        newSnapshot.add(name, s);
    }

    int n = 0;
    int N = oldSnapshot.size();
    int m = 0;

    while (n<N && m<fileCount) {
        const String8& p = oldSnapshot.keyAt(n);
        const String8& q = newSnapshot.keyAt(m);
        int cmp = p.compare(q);
        if (cmp > 0) {
            // file added
            String8 realFilename(base);
            realFilename.appendPath(q);
            write_update_file(realFilename, q);
            m++;
        }
        else if (cmp < 0) {
            // file removed
            write_delete_file(p);
            n++;
        }
        else {
            // both files exist, check them
            String8 realFilename(base);
            realFilename.appendPath(q);
            const FileState& f = oldSnapshot.valueAt(n);
            const FileState& g = newSnapshot.valueAt(m);

            printf("%s\n", q.string());
            printf("  new: modTime=%d,%d size=%-3d crc32=0x%08x\n",
                    f.modTime_sec, f.modTime_nsec, f.size, f.crc32);
            printf("  old: modTime=%d,%d size=%-3d crc32=0x%08x\n",
                    g.modTime_sec, g.modTime_nsec, g.size, g.crc32);
            if (f.modTime_sec != g.modTime_sec || f.modTime_nsec != g.modTime_nsec
                    || f.size != g.size || f.crc32 != g.crc32) {
                write_update_file(realFilename, p);
            }
            n++;
            m++;
        }
    }

    // these were deleted
    while (n<N) {
        write_delete_file(oldSnapshot.keyAt(n));
        n++;
    }

    // these were added
    while (m<fileCount) {
        const String8& q = newSnapshot.keyAt(m);
        String8 realFilename(base);
        realFilename.appendPath(q);
        write_update_file(realFilename, q);
        m++;
    }

    err = write_snapshot_file(newSnapshotFD, newSnapshot);

    return 0;
}

#if TEST_BACKUP_HELPERS

#define SCRATCH_DIR "/data/backup_helper_test/"

static int
write_text_file(const char* path, const char* data)
{
    int amt;
    int fd;
    int len;

    fd = creat(path, 0666);
    if (fd == -1) {
        fprintf(stderr, "creat %s failed\n", path);
        return errno;
    }

    len = strlen(data);
    amt = write(fd, data, len);
    if (amt != len) {
        fprintf(stderr, "error (%s) writing to file %s\n", strerror(errno), path);
        return errno;
    }

    close(fd);

    return 0;
}

static int
compare_file(const char* path, const unsigned char* data, int len)
{
    int fd;
    int amt;

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "compare_file error (%s) opening %s\n", strerror(errno), path);
        return errno;
    }

    unsigned char* contents = (unsigned char*)malloc(len);
    if (contents == NULL) {
        fprintf(stderr, "malloc(%d) failed\n", len);
        return ENOMEM;
    }

    bool sizesMatch = true;
    amt = lseek(fd, 0, SEEK_END);
    if (amt != len) {
        fprintf(stderr, "compare_file file length should be %d, was %d\n", len, amt);
        sizesMatch = false;
    }
    lseek(fd, 0, SEEK_SET);

    int readLen = amt < len ? amt : len;
    amt = read(fd, contents, readLen);
    if (amt != readLen) {
        fprintf(stderr, "compare_file read expected %d bytes but got %d\n", len, amt);
    }

    bool contentsMatch = true;
    for (int i=0; i<readLen; i++) {
        if (data[i] != contents[i]) {
            if (contentsMatch) {
                fprintf(stderr, "compare_file contents are different: (index, expected, actual)\n");
                contentsMatch = false;
            }
            fprintf(stderr, "  [%-2d] %02x %02x\n", i, data[i], contents[i]);
        }
    }

    return contentsMatch && sizesMatch ? 0 : 1;
}

int
backup_helper_test_empty()
{
    int err;
    int fd;
    KeyedVector<String8,FileState> snapshot;
    const char* filename = SCRATCH_DIR "backup_helper_test_empty.snap";

    system("rm -r " SCRATCH_DIR);
    mkdir(SCRATCH_DIR, 0777);

    // write
    fd = creat(filename, 0666);
    if (fd == -1) {
        fprintf(stderr, "error creating %s\n", filename);
        return 1;
    }

    err = write_snapshot_file(fd, snapshot);

    close(fd);

    if (err != 0) {
        fprintf(stderr, "write_snapshot_file reported error %d (%s)\n", err, strerror(err));
        return err;
    }

    static const unsigned char correct_data[] = {
        0x53, 0x6e, 0x61, 0x70,  0x00, 0x00, 0x00, 0x00,
        0x46, 0x69, 0x6c, 0x65,  0x10, 0x00, 0x00, 0x00
    };

    err = compare_file(filename, correct_data, sizeof(correct_data));
    if (err != 0) {
        return err;
    }

    // read
    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "error opening for read %s\n", filename);
        return 1;
    }

    KeyedVector<String8,FileState> readSnapshot;
    err = read_snapshot_file(fd, &readSnapshot);
    if (err != 0) {
        fprintf(stderr, "read_snapshot_file failed %d\n", err);
        return err;
    }

    if (readSnapshot.size() != 0) {
        fprintf(stderr, "readSnapshot should be length 0\n");
        return 1;
    }

    return 0;
}

int
backup_helper_test_four()
{
    int err;
    int fd;
    KeyedVector<String8,FileState> snapshot;
    const char* filename = SCRATCH_DIR "backup_helper_test_four.snap";

    system("rm -r " SCRATCH_DIR);
    mkdir(SCRATCH_DIR, 0777);

    // write
    fd = creat(filename, 0666);
    if (fd == -1) {
        fprintf(stderr, "error opening %s\n", filename);
        return 1;
    }

    String8 filenames[4];
    FileState states[4];

    states[0].modTime_sec = 0xfedcba98;
    states[0].modTime_nsec = 0xdeadbeef;
    states[0].size = 0xababbcbc;
    states[0].crc32 = 0x12345678;
    states[0].nameLen = -12;
    filenames[0] = String8("bytes_of_padding");
    snapshot.add(filenames[0], states[0]);

    states[1].modTime_sec = 0x93400031;
    states[1].modTime_nsec = 0xdeadbeef;
    states[1].size = 0x88557766;
    states[1].crc32 = 0x22334422;
    states[1].nameLen = -1;
    filenames[1] = String8("bytes_of_padding3");
    snapshot.add(filenames[1], states[1]);

    states[2].modTime_sec = 0x33221144;
    states[2].modTime_nsec = 0xdeadbeef;
    states[2].size = 0x11223344;
    states[2].crc32 = 0x01122334;
    states[2].nameLen = 0;
    filenames[2] = String8("bytes_of_padding_2");
    snapshot.add(filenames[2], states[2]);

    states[3].modTime_sec = 0x33221144;
    states[3].modTime_nsec = 0xdeadbeef;
    states[3].size = 0x11223344;
    states[3].crc32 = 0x01122334;
    states[3].nameLen = 0;
    filenames[3] = String8("bytes_of_padding__1");
    snapshot.add(filenames[3], states[3]);

    err = write_snapshot_file(fd, snapshot);

    close(fd);

    if (err != 0) {
        fprintf(stderr, "write_snapshot_file reported error %d (%s)\n", err, strerror(err));
        return err;
    }

    static const unsigned char correct_data[] = {
        // header
        0x53, 0x6e, 0x61, 0x70,  0x04, 0x00, 0x00, 0x00,
        0x46, 0x69, 0x6c, 0x65,  0xac, 0x00, 0x00, 0x00,

        // bytes_of_padding
        0x98, 0xba, 0xdc, 0xfe,  0xef, 0xbe, 0xad, 0xde,
        0xbc, 0xbc, 0xab, 0xab,  0x78, 0x56, 0x34, 0x12,
        0x10, 0x00, 0x00, 0x00,  0x62, 0x79, 0x74, 0x65,
        0x73, 0x5f, 0x6f, 0x66,  0x5f, 0x70, 0x61, 0x64,
        0x64, 0x69, 0x6e, 0x67,

        // bytes_of_padding3
        0x31, 0x00, 0x40, 0x93,  0xef, 0xbe, 0xad, 0xde,
        0x66, 0x77, 0x55, 0x88,  0x22, 0x44, 0x33, 0x22,
        0x11, 0x00, 0x00, 0x00,  0x62, 0x79, 0x74, 0x65,
        0x73, 0x5f, 0x6f, 0x66,  0x5f, 0x70, 0x61, 0x64,
        0x64, 0x69, 0x6e, 0x67,  0x33, 0xab, 0xab, 0xab,
        
        // bytes of padding2
        0x44, 0x11, 0x22, 0x33,  0xef, 0xbe, 0xad, 0xde,
        0x44, 0x33, 0x22, 0x11,  0x34, 0x23, 0x12, 0x01,
        0x12, 0x00, 0x00, 0x00,  0x62, 0x79, 0x74, 0x65,
        0x73, 0x5f, 0x6f, 0x66,  0x5f, 0x70, 0x61, 0x64,
        0x64, 0x69, 0x6e, 0x67,  0x5f, 0x32, 0xab, 0xab,
        
        // bytes of padding3
        0x44, 0x11, 0x22, 0x33,  0xef, 0xbe, 0xad, 0xde,
        0x44, 0x33, 0x22, 0x11,  0x34, 0x23, 0x12, 0x01,
        0x13, 0x00, 0x00, 0x00,  0x62, 0x79, 0x74, 0x65,
        0x73, 0x5f, 0x6f, 0x66,  0x5f, 0x70, 0x61, 0x64,
        0x64, 0x69, 0x6e, 0x67,  0x5f, 0x5f, 0x31, 0xab
    };

    err = compare_file(filename, correct_data, sizeof(correct_data));
    if (err != 0) {
        return err;
    }
    
    // read
    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "error opening for read %s\n", filename);
        return 1;
    }


    KeyedVector<String8,FileState> readSnapshot;
    err = read_snapshot_file(fd, &readSnapshot);
    if (err != 0) {
        fprintf(stderr, "read_snapshot_file failed %d\n", err);
        return err;
    }

    if (readSnapshot.size() != 4) {
        fprintf(stderr, "readSnapshot should be length 4 is %d\n", readSnapshot.size());
        return 1;
    }

    bool matched = true;
    for (size_t i=0; i<readSnapshot.size(); i++) {
        const String8& name = readSnapshot.keyAt(i);
        const FileState state = readSnapshot.valueAt(i);

        if (name != filenames[i] || states[i].modTime_sec != state.modTime_sec
                || states[i].modTime_nsec != state.modTime_nsec
                || states[i].size != state.size || states[i].crc32 != states[i].crc32) {
            fprintf(stderr, "state %d expected={%d/%d, 0x%08x, 0x%08x, %3d} '%s'\n"
                            "          actual={%d/%d, 0x%08x, 0x%08x, %3d} '%s'\n", i,
                    states[i].modTime_sec, states[i].modTime_nsec, states[i].size, states[i].crc32,
                    name.length(), filenames[i].string(),
                    state.modTime_sec, state.modTime_nsec, state.size, state.crc32, state.nameLen,
                    name.string());
            matched = false;
        }
    }
    
    return matched ? 0 : 1;
}

static int
get_mod_time(const char* filename, struct timeval times[2])
{
    int err;
    struct stat64 st;
    err = stat64(filename, &st);
    if (err != 0) {
        fprintf(stderr, "stat '%s' failed: %s\n", filename, strerror(errno));
        return errno;
    }
    times[0].tv_sec = st.st_atime;
    times[0].tv_usec = st.st_atime_nsec / 1000;
    times[1].tv_sec = st.st_mtime;
    times[1].tv_usec = st.st_mtime_nsec / 1000;
    return 0;
}

int
backup_helper_test_files()
{
    int err;
    int newSnapshotFD;
    int oldSnapshotFD;

    system("rm -r " SCRATCH_DIR);
    mkdir(SCRATCH_DIR, 0777);
    mkdir(SCRATCH_DIR "data", 0777);

    write_text_file(SCRATCH_DIR "data/b", "b\nbb\n");
    write_text_file(SCRATCH_DIR "data/c", "c\ncc\n");
    write_text_file(SCRATCH_DIR "data/d", "d\ndd\n");
    write_text_file(SCRATCH_DIR "data/e", "e\nee\n");
    write_text_file(SCRATCH_DIR "data/f", "f\nff\n");
    write_text_file(SCRATCH_DIR "data/h", "h\nhh\n");

    char const* files_before[] = {
        "data/b",
        "data/c",
        "data/d",
        "data/e",
        "data/f"
    };

    newSnapshotFD = creat(SCRATCH_DIR "before.snap", 0666);
    if (newSnapshotFD == -1) {
        fprintf(stderr, "error creating: %s\n", strerror(errno));
        return errno;
    }

    err = back_up_files(-1, newSnapshotFD, 0, SCRATCH_DIR, files_before, 5);
    if (err != 0) {
        return err;
    }

    close(newSnapshotFD);

    sleep(3);

    struct timeval d_times[2];
    struct timeval e_times[2];

    err = get_mod_time(SCRATCH_DIR "data/d", d_times);
    err |= get_mod_time(SCRATCH_DIR "data/e", e_times);
    if (err != 0) {
        return err;
    }

    write_text_file(SCRATCH_DIR "data/a", "a\naa\n");
    unlink(SCRATCH_DIR "data/c");
    write_text_file(SCRATCH_DIR "data/c", "c\ncc\n");
    write_text_file(SCRATCH_DIR "data/d", "dd\ndd\n");
    utimes(SCRATCH_DIR "data/d", d_times);
    write_text_file(SCRATCH_DIR "data/e", "z\nzz\n");
    utimes(SCRATCH_DIR "data/e", e_times);
    write_text_file(SCRATCH_DIR "data/g", "g\ngg\n");
    unlink(SCRATCH_DIR "data/f");
    
    char const* files_after[] = {
        "data/a", // added
        "data/b", // same
        "data/c", // different mod time
        "data/d", // different size (same mod time)
        "data/e", // different contents (same mod time, same size)
        "data/g"  // added
    };

    oldSnapshotFD = open(SCRATCH_DIR "before.snap", O_RDONLY);
    if (oldSnapshotFD == -1) {
        fprintf(stderr, "error opening: %s\n", strerror(errno));
        return errno;
    }

    newSnapshotFD = creat(SCRATCH_DIR "after.snap", 0666);
    if (newSnapshotFD == -1) {
        fprintf(stderr, "error creating: %s\n", strerror(errno));
        return errno;
    }

    err = back_up_files(oldSnapshotFD, newSnapshotFD, 0, SCRATCH_DIR, files_after, 6);
    if (err != 0) {
        return err;
    }

    close(oldSnapshotFD);
    close(newSnapshotFD);
    
    return 0;
}

#endif // TEST_BACKUP_HELPERS
