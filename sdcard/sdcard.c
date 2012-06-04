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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/uio.h>
#include <dirent.h>
#include <limits.h>
#include <ctype.h>
#include <pthread.h>

#include <private/android_filesystem_config.h>

#include "fuse.h"

/* README
 *
 * What is this?
 * 
 * sdcard is a program that uses FUSE to emulate FAT-on-sdcard style
 * directory permissions (all files are given fixed owner, group, and 
 * permissions at creation, owner, group, and permissions are not 
 * changeable, symlinks and hardlinks are not createable, etc.
 *
 * usage:  sdcard <path> <uid> <gid>
 *
 * It must be run as root, but will change to uid/gid as soon as it
 * mounts a filesystem on /storage/sdcard.  It will refuse to run if uid or
 * gid are zero.
 *
 *
 * Things I believe to be true:
 *
 * - ops that return a fuse_entry (LOOKUP, MKNOD, MKDIR, LINK, SYMLINK,
 * CREAT) must bump that node's refcount
 * - don't forget that FORGET can forget multiple references (req->nlookup)
 * - if an op that returns a fuse_entry fails writing the reply to the
 * kernel, you must rollback the refcount to reflect the reference the
 * kernel did not actually acquire
 *
 */

#define FUSE_TRACE 0

#if FUSE_TRACE
#define TRACE(x...) fprintf(stderr,x)
#else
#define TRACE(x...) do {} while (0)
#endif

#define ERROR(x...) fprintf(stderr,x)

#define FUSE_UNKNOWN_INO 0xffffffff

#define MOUNT_POINT "/storage/sdcard0"

/* Maximum number of bytes to write in one request. */
#define MAX_WRITE (256 * 1024)

/* Maximum number of bytes to read in one request. */
#define MAX_READ (128 * 1024)

/* Largest possible request.
 * The request size is bounded by the maximum size of a FUSE_WRITE request because it has
 * the largest possible data payload. */
#define MAX_REQUEST_SIZE (sizeof(struct fuse_in_header) + sizeof(struct fuse_write_in) + MAX_WRITE)

/* Default number of threads. */
#define DEFAULT_NUM_THREADS 2

/* Pseudo-error constant used to indicate that no fuse status is needed
 * or that a reply has already been written. */
#define NO_STATUS 1

struct handle {
    int fd;
};

struct dirhandle {
    DIR *d;
};

struct node {
    __u32 refcount;
    __u64 nid;
    __u64 gen;

    struct node *next;          /* per-dir sibling list */
    struct node *child;         /* first contained file by this dir */
    struct node *parent;        /* containing directory */

    size_t namelen;
    char *name;
    /* If non-null, this is the real name of the file in the underlying storage.
     * This may differ from the field "name" only by case.
     * strlen(actual_name) will always equal strlen(name), so it is safe to use
     * namelen for both fields.
     */
    char *actual_name;
};

/* Global data structure shared by all fuse handlers. */
struct fuse {
    pthread_mutex_t lock;

    __u64 next_generation;
    int fd;
    struct node root;
    char rootpath[PATH_MAX];
};

/* Private data used by a single fuse handler. */
struct fuse_handler {
    struct fuse* fuse;
    int token;

    /* To save memory, we never use the contents of the request buffer and the read
     * buffer at the same time.  This allows us to share the underlying storage. */
    union {
        __u8 request_buffer[MAX_REQUEST_SIZE];
        __u8 read_buffer[MAX_READ];
    };
};

static inline void *id_to_ptr(__u64 nid)
{
    return (void *) (uintptr_t) nid;
}

static inline __u64 ptr_to_id(void *ptr)
{
    return (__u64) (uintptr_t) ptr;
}

static void acquire_node_locked(struct node* node)
{
    node->refcount++;
    TRACE("ACQUIRE %p (%s) rc=%d\n", node, node->name, node->refcount);
}

static void remove_node_from_parent_locked(struct node* node);

static void release_node_locked(struct node* node)
{
    TRACE("RELEASE %p (%s) rc=%d\n", node, node->name, node->refcount);
    if (node->refcount > 0) {
        node->refcount--;
        if (!node->refcount) {
            TRACE("DESTROY %p (%s)\n", node, node->name);
            remove_node_from_parent_locked(node);

                /* TODO: remove debugging - poison memory */
            memset(node->name, 0xef, node->namelen);
            free(node->name);
            free(node->actual_name);
            memset(node, 0xfc, sizeof(*node));
            free(node);
        }
    } else {
        ERROR("Zero refcnt %p\n", node);
    }
}

static void add_node_to_parent_locked(struct node *node, struct node *parent) {
    node->parent = parent;
    node->next = parent->child;
    parent->child = node;
    acquire_node_locked(parent);
}

static void remove_node_from_parent_locked(struct node* node)
{
    if (node->parent) {
        if (node->parent->child == node) {
            node->parent->child = node->parent->child->next;
        } else {
            struct node *node2;
            node2 = node->parent->child;
            while (node2->next != node)
                node2 = node2->next;
            node2->next = node->next;
        }
        release_node_locked(node->parent);
        node->parent = NULL;
        node->next = NULL;
    }
}

/* Gets the absolute path to a node into the provided buffer.
 *
 * Populates 'buf' with the path and returns the length of the path on success,
 * or returns -1 if the path is too long for the provided buffer.
 */
static ssize_t get_node_path_locked(struct node* node, char* buf, size_t bufsize)
{
    size_t namelen = node->namelen;
    if (bufsize < namelen + 1) {
        return -1;
    }

    ssize_t pathlen = 0;
    if (node->parent) {
        pathlen = get_node_path_locked(node->parent, buf, bufsize - namelen - 2);
        if (pathlen < 0) {
            return -1;
        }
        buf[pathlen++] = '/';
    }

    const char* name = node->actual_name ? node->actual_name : node->name;
    memcpy(buf + pathlen, name, namelen + 1); /* include trailing \0 */
    return pathlen + namelen;
}

/* Finds the absolute path of a file within a given directory.
 * Performs a case-insensitive search for the file and sets the buffer to the path
 * of the first matching file.  If 'search' is zero or if no match is found, sets
 * the buffer to the path that the file would have, assuming the name were case-sensitive.
 *
 * Populates 'buf' with the path and returns the actual name (within 'buf') on success,
 * or returns NULL if the path is too long for the provided buffer.
 */
static char* find_file_within(const char* path, const char* name,
        char* buf, size_t bufsize, int search)
{
    size_t pathlen = strlen(path);
    size_t namelen = strlen(name);
    size_t childlen = pathlen + namelen + 1;
    char* actual;

    if (bufsize <= childlen) {
        return NULL;
    }

    memcpy(buf, path, pathlen);
    buf[pathlen] = '/';
    actual = buf + pathlen + 1;
    memcpy(actual, name, namelen + 1);

    if (search && access(buf, F_OK)) {
        struct dirent* entry;
        DIR* dir = opendir(path);
        if (!dir) {
            ERROR("opendir %s failed: %s", path, strerror(errno));
            return actual;
        }
        while ((entry = readdir(dir))) {
            if (!strcasecmp(entry->d_name, name)) {
                /* we have a match - replace the name, don't need to copy the null again */
                memcpy(actual, entry->d_name, namelen);
                break;
            }
        }
        closedir(dir);
    }
    return actual;
}

static void attr_from_stat(struct fuse_attr *attr, const struct stat *s, __u64 nid)
{
    attr->ino = nid;
    attr->size = s->st_size;
    attr->blocks = s->st_blocks;
    attr->atime = s->st_atime;
    attr->mtime = s->st_mtime;
    attr->ctime = s->st_ctime;
    attr->atimensec = s->st_atime_nsec;
    attr->mtimensec = s->st_mtime_nsec;
    attr->ctimensec = s->st_ctime_nsec;
    attr->mode = s->st_mode;
    attr->nlink = s->st_nlink;

        /* force permissions to something reasonable:
         * world readable
         * writable by the sdcard group
         */
    if (attr->mode & 0100) {
        attr->mode = (attr->mode & (~0777)) | 0775;
    } else {
        attr->mode = (attr->mode & (~0777)) | 0664;
    }

        /* all files owned by root.sdcard */
    attr->uid = 0;
    attr->gid = AID_SDCARD_RW;
}

struct node *create_node_locked(struct fuse* fuse,
        struct node *parent, const char *name, const char* actual_name)
{
    struct node *node;
    size_t namelen = strlen(name);

    node = calloc(1, sizeof(struct node));
    if (!node) {
        return NULL;
    }
    node->name = malloc(namelen + 1);
    if (!node->name) {
        free(node);
        return NULL;
    }
    memcpy(node->name, name, namelen + 1);
    if (strcmp(name, actual_name)) {
        node->actual_name = malloc(namelen + 1);
        if (!node->actual_name) {
            free(node->name);
            free(node);
            return NULL;
        }
        memcpy(node->actual_name, actual_name, namelen + 1);
    }
    node->namelen = namelen;
    node->nid = ptr_to_id(node);
    node->gen = fuse->next_generation++;
    acquire_node_locked(node);
    add_node_to_parent_locked(node, parent);
    return node;
}

static int rename_node_locked(struct node *node, const char *name,
        const char* actual_name)
{
    size_t namelen = strlen(name);
    int need_actual_name = strcmp(name, actual_name);

    /* make the storage bigger without actually changing the name
     * in case an error occurs part way */
    if (namelen > node->namelen) {
        char* new_name = realloc(node->name, namelen + 1);
        if (!new_name) {
            return -ENOMEM;
        }
        node->name = new_name;
        if (need_actual_name && node->actual_name) {
            char* new_actual_name = realloc(node->actual_name, namelen + 1);
            if (!new_actual_name) {
                return -ENOMEM;
            }
            node->actual_name = new_actual_name;
        }
    }

    /* update the name, taking care to allocate storage before overwriting the old name */
    if (need_actual_name) {
        if (!node->actual_name) {
            node->actual_name = malloc(namelen + 1);
            if (!node->actual_name) {
                return -ENOMEM;
            }
        }
        memcpy(node->actual_name, actual_name, namelen + 1);
    } else {
        free(node->actual_name);
        node->actual_name = NULL;
    }
    memcpy(node->name, name, namelen + 1);
    node->namelen = namelen;
    return 0;
}

static struct node *lookup_node_by_id_locked(struct fuse *fuse, __u64 nid)
{
    if (nid == FUSE_ROOT_ID) {
        return &fuse->root;
    } else {
        return id_to_ptr(nid);
    }
}

static struct node* lookup_node_and_path_by_id_locked(struct fuse* fuse, __u64 nid,
        char* buf, size_t bufsize)
{
    struct node* node = lookup_node_by_id_locked(fuse, nid);
    if (node && get_node_path_locked(node, buf, bufsize) < 0) {
        node = NULL;
    }
    return node;
}

static struct node *lookup_child_by_name_locked(struct node *node, const char *name)
{
    for (node = node->child; node; node = node->next) {
        /* use exact string comparison, nodes that differ by case
         * must be considered distinct even if they refer to the same
         * underlying file as otherwise operations such as "mv x x"
         * will not work because the source and target nodes are the same. */
        if (!strcmp(name, node->name)) {
            return node;
        }
    }
    return 0;
}

static struct node* acquire_or_create_child_locked(
        struct fuse* fuse, struct node* parent,
        const char* name, const char* actual_name)
{
    struct node* child = lookup_child_by_name_locked(parent, name);
    if (child) {
        acquire_node_locked(child);
    } else {
        child = create_node_locked(fuse, parent, name, actual_name);
    }
    return child;
}

static void fuse_init(struct fuse *fuse, int fd, const char *path)
{
    pthread_mutex_init(&fuse->lock, NULL);

    fuse->fd = fd;
    fuse->next_generation = 0;

    memset(&fuse->root, 0, sizeof(fuse->root));
    fuse->root.nid = FUSE_ROOT_ID; /* 1 */
    fuse->root.refcount = 2;
    fuse->root.namelen = strlen(path);
    fuse->root.name = strdup(path);
}

static void fuse_status(struct fuse *fuse, __u64 unique, int err)
{
    struct fuse_out_header hdr;
    hdr.len = sizeof(hdr);
    hdr.error = err;
    hdr.unique = unique;
    write(fuse->fd, &hdr, sizeof(hdr));
}

static void fuse_reply(struct fuse *fuse, __u64 unique, void *data, int len)
{
    struct fuse_out_header hdr;
    struct iovec vec[2];
    int res;

    hdr.len = len + sizeof(hdr);
    hdr.error = 0;
    hdr.unique = unique;

    vec[0].iov_base = &hdr;
    vec[0].iov_len = sizeof(hdr);
    vec[1].iov_base = data;
    vec[1].iov_len = len;

    res = writev(fuse->fd, vec, 2);
    if (res < 0) {
        ERROR("*** REPLY FAILED *** %d\n", errno);
    }
}

static int fuse_reply_entry(struct fuse* fuse, __u64 unique,
        struct node* parent, const char* name, const char* actual_name,
        const char* path)
{
    struct node* node;
    struct fuse_entry_out out;
    struct stat s;

    if (lstat(path, &s) < 0) {
        return -errno;
    }

    pthread_mutex_lock(&fuse->lock);
    node = acquire_or_create_child_locked(fuse, parent, name, actual_name);
    if (!node) {
        pthread_mutex_unlock(&fuse->lock);
        return -ENOMEM;
    }
    memset(&out, 0, sizeof(out));
    attr_from_stat(&out.attr, &s, node->nid);
    out.attr_valid = 10;
    out.entry_valid = 10;
    out.nodeid = node->nid;
    out.generation = node->gen;
    pthread_mutex_unlock(&fuse->lock);
    fuse_reply(fuse, unique, &out, sizeof(out));
    return NO_STATUS;
}

static int fuse_reply_attr(struct fuse* fuse, __u64 unique, __u64 nid,
        const char* path)
{
    struct fuse_attr_out out;
    struct stat s;

    if (lstat(path, &s) < 0) {
        return -errno;
    }
    memset(&out, 0, sizeof(out));
    attr_from_stat(&out.attr, &s, nid);
    out.attr_valid = 10;
    fuse_reply(fuse, unique, &out, sizeof(out));
    return NO_STATUS;
}

static int handle_lookup(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header *hdr, const char* name)
{
    struct node* parent_node;
    char parent_path[PATH_MAX];
    char child_path[PATH_MAX];
    const char* actual_name;

    pthread_mutex_lock(&fuse->lock);
    parent_node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid,
            parent_path, sizeof(parent_path));
    TRACE("[%d] LOOKUP %s @ %llx (%s)\n", handler->token, name, hdr->nodeid,
        parent_node ? parent_node->name : "?");
    pthread_mutex_unlock(&fuse->lock);

    if (!parent_node || !(actual_name = find_file_within(parent_path, name,
            child_path, sizeof(child_path), 1))) {
        return -ENOENT;
    }
    return fuse_reply_entry(fuse, hdr->unique, parent_node, name, actual_name, child_path);
}

static int handle_forget(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header *hdr, const struct fuse_forget_in *req)
{
    struct node* node;

    pthread_mutex_lock(&fuse->lock);
    node = lookup_node_by_id_locked(fuse, hdr->nodeid);
    TRACE("[%d] FORGET #%lld @ %llx (%s)\n", handler->token, req->nlookup,
            hdr->nodeid, node ? node->name : "?");
    if (node) {
        __u64 n = req->nlookup;
        while (n--) {
            release_node_locked(node);
        }
    }
    pthread_mutex_unlock(&fuse->lock);
    return NO_STATUS; /* no reply */
}

static int handle_getattr(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header *hdr, const struct fuse_getattr_in *req)
{
    struct node* node;
    char path[PATH_MAX];

    pthread_mutex_lock(&fuse->lock);
    node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid, path, sizeof(path));
    TRACE("[%d] GETATTR flags=%x fh=%llx @ %llx (%s)\n", handler->token,
            req->getattr_flags, req->fh, hdr->nodeid, node ? node->name : "?");
    pthread_mutex_unlock(&fuse->lock);

    if (!node) {
        return -ENOENT;
    }
    return fuse_reply_attr(fuse, hdr->unique, hdr->nodeid, path);
}

static int handle_setattr(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header *hdr, const struct fuse_setattr_in *req)
{
    struct node* node;
    char path[PATH_MAX];
    struct timespec times[2];

    pthread_mutex_lock(&fuse->lock);
    node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid, path, sizeof(path));
    TRACE("[%d] SETATTR fh=%llx valid=%x @ %llx (%s)\n", handler->token,
            req->fh, req->valid, hdr->nodeid, node ? node->name : "?");
    pthread_mutex_unlock(&fuse->lock);

    if (!node) {
        return -ENOENT;
    }

    /* XXX: incomplete implementation on purpose.
     * chmod/chown should NEVER be implemented.*/

    if ((req->valid & FATTR_SIZE) && truncate(path, req->size) < 0) {
        return -errno;
    }

    /* Handle changing atime and mtime.  If FATTR_ATIME_and FATTR_ATIME_NOW
     * are both set, then set it to the current time.  Else, set it to the
     * time specified in the request.  Same goes for mtime.  Use utimensat(2)
     * as it allows ATIME and MTIME to be changed independently, and has
     * nanosecond resolution which fuse also has.
     */
    if (req->valid & (FATTR_ATIME | FATTR_MTIME)) {
        times[0].tv_nsec = UTIME_OMIT;
        times[1].tv_nsec = UTIME_OMIT;
        if (req->valid & FATTR_ATIME) {
            if (req->valid & FATTR_ATIME_NOW) {
              times[0].tv_nsec = UTIME_NOW;
            } else {
              times[0].tv_sec = req->atime;
              times[0].tv_nsec = req->atimensec;
            }
        }
        if (req->valid & FATTR_MTIME) {
            if (req->valid & FATTR_MTIME_NOW) {
              times[1].tv_nsec = UTIME_NOW;
            } else {
              times[1].tv_sec = req->mtime;
              times[1].tv_nsec = req->mtimensec;
            }
        }
        TRACE("[%d] Calling utimensat on %s with atime %ld, mtime=%ld\n",
                handler->token, path, times[0].tv_sec, times[1].tv_sec);
        if (utimensat(-1, path, times, 0) < 0) {
            return -errno;
        }
    }
    return fuse_reply_attr(fuse, hdr->unique, hdr->nodeid, path);
}

static int handle_mknod(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const struct fuse_mknod_in* req, const char* name)
{
    struct node* parent_node;
    char parent_path[PATH_MAX];
    char child_path[PATH_MAX];
    const char* actual_name;

    pthread_mutex_lock(&fuse->lock);
    parent_node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid,
            parent_path, sizeof(parent_path));
    TRACE("[%d] MKNOD %s 0%o @ %llx (%s)\n", handler->token,
            name, req->mode, hdr->nodeid, parent_node ? parent_node->name : "?");
    pthread_mutex_unlock(&fuse->lock);

    if (!parent_node || !(actual_name = find_file_within(parent_path, name,
            child_path, sizeof(child_path), 1))) {
        return -ENOENT;
    }
    __u32 mode = (req->mode & (~0777)) | 0664;
    if (mknod(child_path, mode, req->rdev) < 0) {
        return -errno;
    }
    return fuse_reply_entry(fuse, hdr->unique, parent_node, name, actual_name, child_path);
}

static int handle_mkdir(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const struct fuse_mkdir_in* req, const char* name)
{
    struct node* parent_node;
    char parent_path[PATH_MAX];
    char child_path[PATH_MAX];
    const char* actual_name;

    pthread_mutex_lock(&fuse->lock);
    parent_node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid,
            parent_path, sizeof(parent_path));
    TRACE("[%d] MKDIR %s 0%o @ %llx (%s)\n", handler->token,
            name, req->mode, hdr->nodeid, parent_node ? parent_node->name : "?");
    pthread_mutex_unlock(&fuse->lock);

    if (!parent_node || !(actual_name = find_file_within(parent_path, name,
            child_path, sizeof(child_path), 1))) {
        return -ENOENT;
    }
    __u32 mode = (req->mode & (~0777)) | 0775;
    if (mkdir(child_path, mode) < 0) {
        return -errno;
    }
    return fuse_reply_entry(fuse, hdr->unique, parent_node, name, actual_name, child_path);
}

static int handle_unlink(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const char* name)
{
    struct node* parent_node;
    char parent_path[PATH_MAX];
    char child_path[PATH_MAX];

    pthread_mutex_lock(&fuse->lock);
    parent_node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid,
            parent_path, sizeof(parent_path));
    TRACE("[%d] UNLINK %s @ %llx (%s)\n", handler->token,
            name, hdr->nodeid, parent_node ? parent_node->name : "?");
    pthread_mutex_unlock(&fuse->lock);

    if (!parent_node || !find_file_within(parent_path, name,
            child_path, sizeof(child_path), 1)) {
        return -ENOENT;
    }
    if (unlink(child_path) < 0) {
        return -errno;
    }
    return 0;
}

static int handle_rmdir(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const char* name)
{
    struct node* parent_node;
    char parent_path[PATH_MAX];
    char child_path[PATH_MAX];

    pthread_mutex_lock(&fuse->lock);
    parent_node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid,
            parent_path, sizeof(parent_path));
    TRACE("[%d] RMDIR %s @ %llx (%s)\n", handler->token,
            name, hdr->nodeid, parent_node ? parent_node->name : "?");
    pthread_mutex_unlock(&fuse->lock);

    if (!parent_node || !find_file_within(parent_path, name,
            child_path, sizeof(child_path), 1)) {
        return -ENOENT;
    }
    if (rmdir(child_path) < 0) {
        return -errno;
    }
    return 0;
}

static int handle_rename(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const struct fuse_rename_in* req,
        const char* old_name, const char* new_name)
{
    struct node* old_parent_node;
    struct node* new_parent_node;
    struct node* child_node;
    char old_parent_path[PATH_MAX];
    char new_parent_path[PATH_MAX];
    char old_child_path[PATH_MAX];
    char new_child_path[PATH_MAX];
    const char* new_actual_name;
    int res;

    pthread_mutex_lock(&fuse->lock);
    old_parent_node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid,
            old_parent_path, sizeof(old_parent_path));
    new_parent_node = lookup_node_and_path_by_id_locked(fuse, req->newdir,
            new_parent_path, sizeof(new_parent_path));
    TRACE("[%d] RENAME %s->%s @ %llx (%s) -> %llx (%s)\n", handler->token,
            old_name, new_name,
            hdr->nodeid, old_parent_node ? old_parent_node->name : "?",
            req->newdir, new_parent_node ? new_parent_node->name : "?");
    if (!old_parent_node || !new_parent_node) {
        res = -ENOENT;
        goto lookup_error;
    }
    child_node = lookup_child_by_name_locked(old_parent_node, old_name);
    if (!child_node || get_node_path_locked(child_node,
            old_child_path, sizeof(old_child_path)) < 0) {
        res = -ENOENT;
        goto lookup_error;
    }
    acquire_node_locked(child_node);
    pthread_mutex_unlock(&fuse->lock);

    /* Special case for renaming a file where destination is same path
     * differing only by case.  In this case we don't want to look for a case
     * insensitive match.  This allows commands like "mv foo FOO" to work as expected.
     */
    int search = old_parent_node != new_parent_node
            || strcasecmp(old_name, new_name);
    if (!(new_actual_name = find_file_within(new_parent_path, new_name,
            new_child_path, sizeof(new_child_path), search))) {
        res = -ENOENT;
        goto io_error;
    }

    TRACE("[%d] RENAME %s->%s\n", handler->token, old_child_path, new_child_path);
    res = rename(old_child_path, new_child_path);
    if (res < 0) {
        res = -errno;
        goto io_error;
    }

    pthread_mutex_lock(&fuse->lock);
    res = rename_node_locked(child_node, new_name, new_actual_name);
    if (!res) {
        remove_node_from_parent_locked(child_node);
        add_node_to_parent_locked(child_node, new_parent_node);
    }
    goto done;

io_error:
    pthread_mutex_lock(&fuse->lock);
done:
    release_node_locked(child_node);
lookup_error:
    pthread_mutex_unlock(&fuse->lock);
    return res;
}

static int handle_open(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const struct fuse_open_in* req)
{
    struct node* node;
    char path[PATH_MAX];
    struct fuse_open_out out;
    struct handle *h;

    pthread_mutex_lock(&fuse->lock);
    node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid, path, sizeof(path));
    TRACE("[%d] OPEN 0%o @ %llx (%s)\n", handler->token,
            req->flags, hdr->nodeid, node ? node->name : "?");
    pthread_mutex_unlock(&fuse->lock);

    if (!node) {
        return -ENOENT;
    }
    h = malloc(sizeof(*h));
    if (!h) {
        return -ENOMEM;
    }
    TRACE("[%d] OPEN %s\n", handler->token, path);
    h->fd = open(path, req->flags);
    if (h->fd < 0) {
        free(h);
        return -errno;
    }
    out.fh = ptr_to_id(h);
    out.open_flags = 0;
    out.padding = 0;
    fuse_reply(fuse, hdr->unique, &out, sizeof(out));
    return NO_STATUS;
}

static int handle_read(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const struct fuse_read_in* req)
{
    struct handle *h = id_to_ptr(req->fh);
    __u64 unique = hdr->unique;
    __u32 size = req->size;
    __u64 offset = req->offset;
    int res;

    /* Don't access any other fields of hdr or req beyond this point, the read buffer
     * overlaps the request buffer and will clobber data in the request.  This
     * saves us 128KB per request handler thread at the cost of this scary comment. */

    TRACE("[%d] READ %p(%d) %u@%llu\n", handler->token,
            h, h->fd, size, offset);
    if (size > sizeof(handler->read_buffer)) {
        return -EINVAL;
    }
    res = pread64(h->fd, handler->read_buffer, size, offset);
    if (res < 0) {
        return -errno;
    }
    fuse_reply(fuse, unique, handler->read_buffer, res);
    return NO_STATUS;
}

static int handle_write(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const struct fuse_write_in* req,
        const void* buffer)
{
    struct fuse_write_out out;
    struct handle *h = id_to_ptr(req->fh);
    int res;

    TRACE("[%d] WRITE %p(%d) %u@%llu\n", handler->token,
            h, h->fd, req->size, req->offset);
    res = pwrite64(h->fd, buffer, req->size, req->offset);
    if (res < 0) {
        return -errno;
    }
    out.size = res;
    fuse_reply(fuse, hdr->unique, &out, sizeof(out));
    return NO_STATUS;
}

static int handle_statfs(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr)
{
    char path[PATH_MAX];
    struct statfs stat;
    struct fuse_statfs_out out;
    int res;

    pthread_mutex_lock(&fuse->lock);
    TRACE("[%d] STATFS\n", handler->token);
    res = get_node_path_locked(&fuse->root, path, sizeof(path));
    pthread_mutex_unlock(&fuse->lock);
    if (res < 0) {
        return -ENOENT;
    }
    if (statfs(fuse->root.name, &stat) < 0) {
        return -errno;
    }
    memset(&out, 0, sizeof(out));
    out.st.blocks = stat.f_blocks;
    out.st.bfree = stat.f_bfree;
    out.st.bavail = stat.f_bavail;
    out.st.files = stat.f_files;
    out.st.ffree = stat.f_ffree;
    out.st.bsize = stat.f_bsize;
    out.st.namelen = stat.f_namelen;
    out.st.frsize = stat.f_frsize;
    fuse_reply(fuse, hdr->unique, &out, sizeof(out));
    return NO_STATUS;
}

static int handle_release(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const struct fuse_release_in* req)
{
    struct handle *h = id_to_ptr(req->fh);

    TRACE("[%d] RELEASE %p(%d)\n", handler->token, h, h->fd);
    close(h->fd);
    free(h);
    return 0;
}

static int handle_fsync(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const struct fuse_fsync_in* req)
{
    int is_data_sync = req->fsync_flags & 1;
    struct handle *h = id_to_ptr(req->fh);
    int res;

    TRACE("[%d] FSYNC %p(%d) is_data_sync=%d\n", handler->token,
            h, h->fd, is_data_sync);
    res = is_data_sync ? fdatasync(h->fd) : fsync(h->fd);
    if (res < 0) {
        return -errno;
    }
    return 0;
}

static int handle_flush(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr)
{
    TRACE("[%d] FLUSH\n", handler->token);
    return 0;
}

static int handle_opendir(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const struct fuse_open_in* req)
{
    struct node* node;
    char path[PATH_MAX];
    struct fuse_open_out out;
    struct dirhandle *h;

    pthread_mutex_lock(&fuse->lock);
    node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid, path, sizeof(path));
    TRACE("[%d] OPENDIR @ %llx (%s)\n", handler->token,
            hdr->nodeid, node ? node->name : "?");
    pthread_mutex_unlock(&fuse->lock);

    if (!node) {
        return -ENOENT;
    }
    h = malloc(sizeof(*h));
    if (!h) {
        return -ENOMEM;
    }
    TRACE("[%d] OPENDIR %s\n", handler->token, path);
    h->d = opendir(path);
    if (!h->d) {
        free(h);
        return -errno;
    }
    out.fh = ptr_to_id(h);
    fuse_reply(fuse, hdr->unique, &out, sizeof(out));
    return NO_STATUS;
}

static int handle_readdir(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const struct fuse_read_in* req)
{
    char buffer[8192];
    struct fuse_dirent *fde = (struct fuse_dirent*) buffer;
    struct dirent *de;
    struct dirhandle *h = id_to_ptr(req->fh);

    TRACE("[%d] READDIR %p\n", handler->token, h);
    if (req->offset == 0) {
        /* rewinddir() might have been called above us, so rewind here too */
        TRACE("[%d] calling rewinddir()\n", handler->token);
        rewinddir(h->d);
    }
    de = readdir(h->d);
    if (!de) {
        return 0;
    }
    fde->ino = FUSE_UNKNOWN_INO;
    /* increment the offset so we can detect when rewinddir() seeks back to the beginning */
    fde->off = req->offset + 1;
    fde->type = de->d_type;
    fde->namelen = strlen(de->d_name);
    memcpy(fde->name, de->d_name, fde->namelen + 1);
    fuse_reply(fuse, hdr->unique, fde,
            FUSE_DIRENT_ALIGN(sizeof(struct fuse_dirent) + fde->namelen));
    return NO_STATUS;
}

static int handle_releasedir(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const struct fuse_release_in* req)
{
    struct dirhandle *h = id_to_ptr(req->fh);

    TRACE("[%d] RELEASEDIR %p\n", handler->token, h);
    closedir(h->d);
    free(h);
    return 0;
}

static int handle_init(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const struct fuse_init_in* req)
{
    struct fuse_init_out out;

    TRACE("[%d] INIT ver=%d.%d maxread=%d flags=%x\n",
            handler->token, req->major, req->minor, req->max_readahead, req->flags);
    out.major = FUSE_KERNEL_VERSION;
    out.minor = FUSE_KERNEL_MINOR_VERSION;
    out.max_readahead = req->max_readahead;
    out.flags = FUSE_ATOMIC_O_TRUNC | FUSE_BIG_WRITES;
    out.max_background = 32;
    out.congestion_threshold = 32;
    out.max_write = MAX_WRITE;
    fuse_reply(fuse, hdr->unique, &out, sizeof(out));
    return NO_STATUS;
}

static int handle_fuse_request(struct fuse *fuse, struct fuse_handler* handler,
        const struct fuse_in_header *hdr, const void *data, size_t data_len)
{
    switch (hdr->opcode) {
    case FUSE_LOOKUP: { /* bytez[] -> entry_out */
        const char* name = data;
        return handle_lookup(fuse, handler, hdr, name);
    }

    case FUSE_FORGET: {
        const struct fuse_forget_in *req = data;
        return handle_forget(fuse, handler, hdr, req);
    }

    case FUSE_GETATTR: { /* getattr_in -> attr_out */
        const struct fuse_getattr_in *req = data;
        return handle_getattr(fuse, handler, hdr, req);
    }

    case FUSE_SETATTR: { /* setattr_in -> attr_out */
        const struct fuse_setattr_in *req = data;
        return handle_setattr(fuse, handler, hdr, req);
    }

//    case FUSE_READLINK:
//    case FUSE_SYMLINK:
    case FUSE_MKNOD: { /* mknod_in, bytez[] -> entry_out */
        const struct fuse_mknod_in *req = data;
        const char *name = ((const char*) data) + sizeof(*req);
        return handle_mknod(fuse, handler, hdr, req, name);
    }

    case FUSE_MKDIR: { /* mkdir_in, bytez[] -> entry_out */
        const struct fuse_mkdir_in *req = data;
        const char *name = ((const char*) data) + sizeof(*req);
        return handle_mkdir(fuse, handler, hdr, req, name);
    }

    case FUSE_UNLINK: { /* bytez[] -> */
        const char* name = data;
        return handle_unlink(fuse, handler, hdr, name);
    }

    case FUSE_RMDIR: { /* bytez[] -> */
        const char* name = data;
        return handle_rmdir(fuse, handler, hdr, name);
    }

    case FUSE_RENAME: { /* rename_in, oldname, newname ->  */
        const struct fuse_rename_in *req = data;
        const char *old_name = ((const char*) data) + sizeof(*req);
        const char *new_name = old_name + strlen(old_name) + 1;
        return handle_rename(fuse, handler, hdr, req, old_name, new_name);
    }

//    case FUSE_LINK:
    case FUSE_OPEN: { /* open_in -> open_out */
        const struct fuse_open_in *req = data;
        return handle_open(fuse, handler, hdr, req);
    }

    case FUSE_READ: { /* read_in -> byte[] */
        const struct fuse_read_in *req = data;
        return handle_read(fuse, handler, hdr, req);
    }

    case FUSE_WRITE: { /* write_in, byte[write_in.size] -> write_out */
        const struct fuse_write_in *req = data;
        const void* buffer = (const __u8*)data + sizeof(*req);
        return handle_write(fuse, handler, hdr, req, buffer);
    }

    case FUSE_STATFS: { /* getattr_in -> attr_out */
        return handle_statfs(fuse, handler, hdr);
    }

    case FUSE_RELEASE: { /* release_in -> */
        const struct fuse_release_in *req = data;
        return handle_release(fuse, handler, hdr, req);
    }

    case FUSE_FSYNC: {
        const struct fuse_fsync_in *req = data;
        return handle_fsync(fuse, handler, hdr, req);
    }

//    case FUSE_SETXATTR:
//    case FUSE_GETXATTR:
//    case FUSE_LISTXATTR:
//    case FUSE_REMOVEXATTR:
    case FUSE_FLUSH: {
        return handle_flush(fuse, handler, hdr);
    }

    case FUSE_OPENDIR: { /* open_in -> open_out */
        const struct fuse_open_in *req = data;
        return handle_opendir(fuse, handler, hdr, req);
    }

    case FUSE_READDIR: {
        const struct fuse_read_in *req = data;
        return handle_readdir(fuse, handler, hdr, req);
    }

    case FUSE_RELEASEDIR: { /* release_in -> */
        const struct fuse_release_in *req = data;
        return handle_releasedir(fuse, handler, hdr, req);
    }

//    case FUSE_FSYNCDIR:
    case FUSE_INIT: { /* init_in -> init_out */
        const struct fuse_init_in *req = data;
        return handle_init(fuse, handler, hdr, req);
    }

    default: {
        TRACE("[%d] NOTIMPL op=%d uniq=%llx nid=%llx\n",
                handler->token, hdr->opcode, hdr->unique, hdr->nodeid);
        return -ENOSYS;
    }
    }
}

static void handle_fuse_requests(struct fuse_handler* handler)
{
    struct fuse* fuse = handler->fuse;
    for (;;) {
        ssize_t len = read(fuse->fd,
                handler->request_buffer, sizeof(handler->request_buffer));
        if (len < 0) {
            if (errno != EINTR) {
                ERROR("[%d] handle_fuse_requests: errno=%d\n", handler->token, errno);
            }
            continue;
        }

        if ((size_t)len < sizeof(struct fuse_in_header)) {
            ERROR("[%d] request too short: len=%zu\n", handler->token, (size_t)len);
            continue;
        }

        const struct fuse_in_header *hdr = (void*)handler->request_buffer;
        if (hdr->len != (size_t)len) {
            ERROR("[%d] malformed header: len=%zu, hdr->len=%u\n",
                    handler->token, (size_t)len, hdr->len);
            continue;
        }

        const void *data = handler->request_buffer + sizeof(struct fuse_in_header);
        size_t data_len = len - sizeof(struct fuse_in_header);
        __u64 unique = hdr->unique;
        int res = handle_fuse_request(fuse, handler, hdr, data, data_len);

        /* We do not access the request again after this point because the underlying
         * buffer storage may have been reused while processing the request. */

        if (res != NO_STATUS) {
            if (res) {
                TRACE("[%d] ERROR %d\n", handler->token, res);
            }
            fuse_status(fuse, unique, res);
        }
    }
}

static void* start_handler(void* data)
{
    struct fuse_handler* handler = data;
    handle_fuse_requests(handler);
    return NULL;
}

static int ignite_fuse(struct fuse* fuse, int num_threads)
{
    struct fuse_handler* handlers;
    int i;

    handlers = malloc(num_threads * sizeof(struct fuse_handler));
    if (!handlers) {
        ERROR("cannot allocate storage for threads");
        return -ENOMEM;
    }

    for (i = 0; i < num_threads; i++) {
        handlers[i].fuse = fuse;
        handlers[i].token = i;
    }

    for (i = 1; i < num_threads; i++) {
        pthread_t thread;
        int res = pthread_create(&thread, NULL, start_handler, &handlers[i]);
        if (res) {
            ERROR("failed to start thread #%d, error=%d", i, res);
            goto quit;
        }
    }
    handle_fuse_requests(&handlers[0]);
    ERROR("terminated prematurely");

    /* don't bother killing all of the other threads or freeing anything,
     * should never get here anyhow */
quit:
    exit(1);
}

static int usage()
{
    ERROR("usage: sdcard [-t<threads>] <path> <uid> <gid>\n"
            "    -t<threads>: specify number of threads to use, default -t%d\n"
            "\n", DEFAULT_NUM_THREADS);
    return 1;
}

static int run(const char* path, uid_t uid, gid_t gid, int num_threads)
{
    int fd;
    char opts[256];
    int res;
    struct fuse fuse;

    /* cleanup from previous instance, if necessary */
    umount2(MOUNT_POINT, 2);

    fd = open("/dev/fuse", O_RDWR);
    if (fd < 0){
        ERROR("cannot open fuse device (error %d)\n", errno);
        return -1;
    }

    snprintf(opts, sizeof(opts),
            "fd=%i,rootmode=40000,default_permissions,allow_other,user_id=%d,group_id=%d",
            fd, uid, gid);

    res = mount("/dev/fuse", MOUNT_POINT, "fuse", MS_NOSUID | MS_NODEV, opts);
    if (res < 0) {
        ERROR("cannot mount fuse filesystem (error %d)\n", errno);
        goto error;
    }

    res = setgid(gid);
    if (res < 0) {
        ERROR("cannot setgid (error %d)\n", errno);
        goto error;
    }

    res = setuid(uid);
    if (res < 0) {
        ERROR("cannot setuid (error %d)\n", errno);
        goto error;
    }

    fuse_init(&fuse, fd, path);

    umask(0);
    res = ignite_fuse(&fuse, num_threads);

    /* we do not attempt to umount the file system here because we are no longer
     * running as the root user */

error:
    close(fd);
    return res;
}

int main(int argc, char **argv)
{
    int res;
    const char *path = NULL;
    uid_t uid = 0;
    gid_t gid = 0;
    int num_threads = DEFAULT_NUM_THREADS;
    int i;

    for (i = 1; i < argc; i++) {
        char* arg = argv[i];
        if (!strncmp(arg, "-t", 2))
            num_threads = strtoul(arg + 2, 0, 10);
        else if (!path)
            path = arg;
        else if (!uid)
            uid = strtoul(arg, 0, 10);
        else if (!gid)
            gid = strtoul(arg, 0, 10);
        else {
            ERROR("too many arguments\n");
            return usage();
        }
    }

    if (!path) {
        ERROR("no path specified\n");
        return usage();
    }
    if (!uid || !gid) {
        ERROR("uid and gid must be nonzero\n");
        return usage();
    }
    if (num_threads < 1) {
        ERROR("number of threads must be at least 1\n");
        return usage();
    }

    res = run(path, uid, gid, num_threads);
    return res < 0 ? 1 : 0;
}
