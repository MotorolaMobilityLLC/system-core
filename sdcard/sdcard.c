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
#include <ctype.h>

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

struct handle {
    struct node *node;
    int fd;
};

struct dirhandle {
    struct node *node;
    DIR *d;
};

struct node {
    __u64 nid;
    __u64 gen;

    struct node *next;          /* per-dir sibling list */
    struct node *child;         /* first contained file by this dir */
    struct node *all;           /* global node list */
    struct node *parent;        /* containing directory */

    __u32 refcount;
    __u32 namelen;

    char *name;
    /* If non-null, this is the real name of the file in the underlying storage.
     * This may differ from the field "name" only by case.
     * strlen(actual_name) will always equal strlen(name), so it is safe to use
     * namelen for both fields.
     */
    char *actual_name;
};

struct fuse {
    __u64 next_generation;
    __u64 next_node_id;

    int fd;

    struct node *all;

    struct node root;
    char rootpath[1024];
};

#define PATH_BUFFER_SIZE 1024

#define NO_CASE_SENSITIVE_MATCH 0
#define CASE_SENSITIVE_MATCH 1

/*
 * Get the real-life absolute path to a node.
 *   node: start at this node
 *   buf: storage for returned string
 *   name: append this string to path if set
 */
char *do_node_get_path(struct node *node, char *buf, const char *name, int match_case_insensitive)
{
    struct node *in_node = node;
    const char *in_name = name;
    char *out = buf + PATH_BUFFER_SIZE - 1;
    int len;
    out[0] = 0;

    if (name) {
        len = strlen(name);
        goto start;
    }

    while (node) {
        name = (node->actual_name ? node->actual_name : node->name);
        len = node->namelen;
        node = node->parent;
    start:
        if ((len + 1) > (out - buf))
            return 0;
        out -= len;
        memcpy(out, name, len);
        /* avoid double slash at beginning of path */
        if (out[0] != '/') {
            out --;
            out[0] = '/';
        }
    }

    /* If we are searching for a file within node (rather than computing node's path)
     * and fail, then we need to look for a case insensitive match.
     */
    if (in_name && match_case_insensitive && access(out, F_OK) != 0) {
        char *path, buffer[PATH_BUFFER_SIZE];
        DIR* dir;
        struct dirent* entry;
        path = do_node_get_path(in_node, buffer, NULL, NO_CASE_SENSITIVE_MATCH);
        dir = opendir(path);
        if (!dir) {
            ERROR("opendir %s failed: %s", path, strerror(errno));
            return out;
        }

        while ((entry = readdir(dir))) {
            if (!strcasecmp(entry->d_name, in_name)) {
                /* we have a match - replace the name */
                len = strlen(in_name);
                memcpy(buf + PATH_BUFFER_SIZE - len - 1, entry->d_name, len);
                break;
            }
        }
        closedir(dir);
    }

   return out;
}

char *node_get_path(struct node *node, char *buf, const char *name)
{
    /* We look for case insensitive matches by default */
    return do_node_get_path(node, buf, name, CASE_SENSITIVE_MATCH);
}

void attr_from_stat(struct fuse_attr *attr, struct stat *s)
{
    attr->ino = s->st_ino;
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

int node_get_attr(struct node *node, struct fuse_attr *attr)
{
    int res;
    struct stat s;
    char *path, buffer[PATH_BUFFER_SIZE];

    path = node_get_path(node, buffer, 0);
    res = lstat(path, &s);
    if (res < 0) {
        ERROR("lstat('%s') errno %d\n", path, errno);
        return -1;
    }

    attr_from_stat(attr, &s);    
    attr->ino = node->nid;

    return 0;
}

static void add_node_to_parent(struct node *node, struct node *parent) {
    node->parent = parent;
    node->next = parent->child;
    parent->child = node;
    parent->refcount++;
}

/* Check to see if our parent directory already has a file with a name
 * that differs only by case.  If we find one, store it in the actual_name
 * field so node_get_path will map it to this file in the underlying storage.
 */
static void node_find_actual_name(struct node *node)
{
    char *path, buffer[PATH_BUFFER_SIZE];
    const char *node_name = node->name;
    DIR* dir;
    struct dirent* entry;

    if (!node->parent) return;

    path = node_get_path(node->parent, buffer, 0);
    dir = opendir(path);
    if (!dir) {
        ERROR("opendir %s failed: %s", path, strerror(errno));
        return;
    }

    while ((entry = readdir(dir))) {
        const char *test_name = entry->d_name;
        if (strcmp(test_name, node_name) && !strcasecmp(test_name, node_name)) {
            /* we have a match - differs but only by case */
            node->actual_name = strdup(test_name);
            if (!node->actual_name) {
                ERROR("strdup failed - out of memory\n");
                exit(1);
            }
            break;
        }
    }
    closedir(dir);
}

struct node *node_create(struct node *parent, const char *name, __u64 nid, __u64 gen)
{
    struct node *node;
    int namelen = strlen(name);

    node = calloc(1, sizeof(struct node));
    if (node == 0) {
        return 0;
    }
    node->name = malloc(namelen + 1);
    if (node->name == 0) {
        free(node);
        return 0;
    }

    node->nid = nid;
    node->gen = gen;
    add_node_to_parent(node, parent);
    memcpy(node->name, name, namelen + 1);
    node->namelen = namelen;
    node_find_actual_name(node);
    return node;
}

static char *rename_node(struct node *node, const char *name)
{
    node->namelen = strlen(name);
    char *newname = realloc(node->name, node->namelen + 1);
    if (newname == 0)
        return 0;
    node->name = newname;
    memcpy(node->name, name, node->namelen + 1);
    node_find_actual_name(node);
    return node->name;
}

void fuse_init(struct fuse *fuse, int fd, const char *path)
{
    fuse->fd = fd;
    fuse->next_node_id = 2;
    fuse->next_generation = 0;

    fuse->all = &fuse->root;

    memset(&fuse->root, 0, sizeof(fuse->root));
    fuse->root.nid = FUSE_ROOT_ID; /* 1 */
    fuse->root.refcount = 2;
    rename_node(&fuse->root, path);
}

static inline void *id_to_ptr(__u64 nid)
{
    return (void *) (uintptr_t) nid;
}

static inline __u64 ptr_to_id(void *ptr)
{
    return (__u64) (uintptr_t) ptr;
}


struct node *lookup_by_inode(struct fuse *fuse, __u64 nid)
{
    if (nid == FUSE_ROOT_ID) {
        return &fuse->root;
    } else {
        return id_to_ptr(nid);
    }
}

struct node *lookup_child_by_name(struct node *node, const char *name)
{
    for (node = node->child; node; node = node->next) {
        if (!strcmp(name, node->name)) {
            return node;
        }
    }
    return 0;
}

struct node *lookup_child_by_inode(struct node *node, __u64 nid)
{
    for (node = node->child; node; node = node->next) {
        if (node->nid == nid) {
            return node;
        }
    }
    return 0;
}

static void dec_refcount(struct node *node) {
    if (node->refcount > 0) {
        node->refcount--;
        TRACE("dec_refcount %p(%s) -> %d\n", node, node->name, node->refcount);
    } else {
        ERROR("Zero refcnt %p\n", node);
    }
 }

static struct node *remove_child(struct node *parent, __u64 nid)
{
    struct node *prev = 0;
    struct node *node;

    for (node = parent->child; node; node = node->next) {
        if (node->nid == nid) {
            if (prev) {
                prev->next = node->next;
            } else {
                parent->child = node->next;
            }
            node->next = 0;
            node->parent = 0;
            dec_refcount(parent);
            return node;
        }
        prev = node;
    }
    return 0;
}

struct node *node_lookup(struct fuse *fuse, struct node *parent, const char *name,
                         struct fuse_attr *attr)
{
    int res;
    struct stat s;
    char *path, buffer[PATH_BUFFER_SIZE];
    struct node *node;

    path = node_get_path(parent, buffer, name);
        /* XXX error? */

    res = lstat(path, &s);
    if (res < 0)
        return 0;
    
    node = lookup_child_by_name(parent, name);
    if (!node) {
        node = node_create(parent, name, fuse->next_node_id++, fuse->next_generation++);
        if (!node)
            return 0;
        node->nid = ptr_to_id(node);
        node->all = fuse->all;
        fuse->all = node;
    }

    attr_from_stat(attr, &s);
    attr->ino = node->nid;

    return node;
}

void node_release(struct node *node)
{
    TRACE("RELEASE %p (%s) rc=%d\n", node, node->name, node->refcount);
    dec_refcount(node);
    if (node->refcount == 0) {
        if (node->parent->child == node) {
            node->parent->child = node->parent->child->next;
        } else {
            struct node *node2;

            node2 = node->parent->child;
            while (node2->next != node)
                node2 = node2->next;
            node2->next = node->next;            
        }

        TRACE("DESTROY %p (%s)\n", node, node->name);

        node_release(node->parent);

        node->parent = 0;
        node->next = 0;

            /* TODO: remove debugging - poison memory */
        memset(node->name, 0xef, node->namelen);
        free(node->name);
        free(node->actual_name);
        memset(node, 0xfc, sizeof(*node));
        free(node);
    }
}

void fuse_status(struct fuse *fuse, __u64 unique, int err)
{
    struct fuse_out_header hdr;
    hdr.len = sizeof(hdr);
    hdr.error = err;
    hdr.unique = unique;
    if (err) {
//        ERROR("*** %d ***\n", err);
    }
    write(fuse->fd, &hdr, sizeof(hdr));
}

void fuse_reply(struct fuse *fuse, __u64 unique, void *data, int len)
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

void lookup_entry(struct fuse *fuse, struct node *node,
                  const char *name, __u64 unique)
{
    struct fuse_entry_out out;
    
    memset(&out, 0, sizeof(out));

    node = node_lookup(fuse, node, name, &out.attr);
    if (!node) {
        fuse_status(fuse, unique, -ENOENT);
        return;
    }
    
    node->refcount++;
//    fprintf(stderr,"ACQUIRE %p (%s) rc=%d\n", node, node->name, node->refcount);
    out.nodeid = node->nid;
    out.generation = node->gen;
    out.entry_valid = 10;
    out.attr_valid = 10;
    
    fuse_reply(fuse, unique, &out, sizeof(out));
}

void handle_fuse_request(struct fuse *fuse,
        const struct fuse_in_header *hdr, const void *data, size_t data_len)
{
    struct node *node;

    if (hdr->nodeid) {
        node = lookup_by_inode(fuse, hdr->nodeid);
        if (!node) {
            fuse_status(fuse, hdr->unique, -ENOENT);
            return;
        }
    } else {
        node = 0;
    }

    switch (hdr->opcode) {
    case FUSE_LOOKUP: { /* bytez[] -> entry_out */
        const char* name = data;
        TRACE("LOOKUP %llx %s\n", hdr->nodeid, name);
        lookup_entry(fuse, node, name, hdr->unique);
        return;
    }

    case FUSE_FORGET: {
        const struct fuse_forget_in *req = data;
        __u64 n = req->nlookup;
        TRACE("FORGET %llx (%s) #%lld\n", hdr->nodeid, node->name, n);
            /* no reply */
        while (n--)
            node_release(node);
        return;
    }

    case FUSE_GETATTR: { /* getattr_in -> attr_out */
        const struct fuse_getattr_in *req = data;
        struct fuse_attr_out out;

        TRACE("GETATTR flags=%x fh=%llx\n", req->getattr_flags, req->fh);

        memset(&out, 0, sizeof(out));
        node_get_attr(node, &out.attr);
        out.attr_valid = 10;

        fuse_reply(fuse, hdr->unique, &out, sizeof(out));
        return;
    }

    case FUSE_SETATTR: { /* setattr_in -> attr_out */
        const struct fuse_setattr_in *req = data;
        struct fuse_attr_out out;
        char *path, buffer[PATH_BUFFER_SIZE];
        int res = 0;
        struct timespec times[2];

        TRACE("SETATTR fh=%llx id=%llx valid=%x\n",
              req->fh, hdr->nodeid, req->valid);

        /* XXX: incomplete implementation on purpose.   chmod/chown
         * should NEVER be implemented.*/

        path = node_get_path(node, buffer, 0);
        if (req->valid & FATTR_SIZE)
            res = truncate(path, req->size);
        if (res)
            goto getout;

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
            TRACE("Calling utimensat on %s with atime %ld, mtime=%ld\n", path, times[0].tv_sec, times[1].tv_sec);
            res = utimensat(-1, path, times, 0);
        }

        getout:
        memset(&out, 0, sizeof(out));
        node_get_attr(node, &out.attr);
        out.attr_valid = 10;

        if (res)
            fuse_status(fuse, hdr->unique, -errno);
        else
            fuse_reply(fuse, hdr->unique, &out, sizeof(out));
        return;
    }

//    case FUSE_READLINK:
//    case FUSE_SYMLINK:
    case FUSE_MKNOD: { /* mknod_in, bytez[] -> entry_out */
        const struct fuse_mknod_in *req = data;
        const char *name = ((const char*) data) + sizeof(*req);
        char *path, buffer[PATH_BUFFER_SIZE];
        int res;

        TRACE("MKNOD %s @ %llx\n", name, hdr->nodeid);
        path = node_get_path(node, buffer, name);

        __u32 mode = (req->mode & (~0777)) | 0664;
        res = mknod(path, mode, req->rdev); /* XXX perm?*/
        if (res < 0) {
            fuse_status(fuse, hdr->unique, -errno);
        } else {
            lookup_entry(fuse, node, name, hdr->unique);
        }
        return;
    }

    case FUSE_MKDIR: { /* mkdir_in, bytez[] -> entry_out */
        const struct fuse_mkdir_in *req = data;
        const char *name = ((const char*) data) + sizeof(*req);
        struct fuse_entry_out out;
        char *path, buffer[PATH_BUFFER_SIZE];
        int res;

        TRACE("MKDIR %s @ %llx 0%o\n", name, hdr->nodeid, req->mode);
        path = node_get_path(node, buffer, name);

        __u32 mode = (req->mode & (~0777)) | 0775;
        res = mkdir(path, mode);
        if (res < 0) {
            fuse_status(fuse, hdr->unique, -errno);
        } else {
            lookup_entry(fuse, node, name, hdr->unique);
        }
        return;
    }

    case FUSE_UNLINK: { /* bytez[] -> */
        const char* name = data;
        char *path, buffer[PATH_BUFFER_SIZE];
        int res;
        TRACE("UNLINK %s @ %llx\n", name, hdr->nodeid);
        path = node_get_path(node, buffer, name);
        res = unlink(path);
        fuse_status(fuse, hdr->unique, res ? -errno : 0);
        return;
    }

    case FUSE_RMDIR: { /* bytez[] -> */
        const char* name = data;
        char *path, buffer[PATH_BUFFER_SIZE];
        int res;
        TRACE("RMDIR %s @ %llx\n", name, hdr->nodeid);
        path = node_get_path(node, buffer, name);
        res = rmdir(path);
        fuse_status(fuse, hdr->unique, res ? -errno : 0);
        return;
    }

    case FUSE_RENAME: { /* rename_in, oldname, newname ->  */
        const struct fuse_rename_in *req = data;
        const char *oldname = ((const char*) data) + sizeof(*req);
        const char *newname = oldname + strlen(oldname) + 1;
        char *oldpath, oldbuffer[PATH_BUFFER_SIZE];
        char *newpath, newbuffer[PATH_BUFFER_SIZE];
        struct node *target;
        struct node *newparent;
        int res;

        TRACE("RENAME %s->%s @ %llx\n", oldname, newname, hdr->nodeid);

        target = lookup_child_by_name(node, oldname);
        if (!target) {
            fuse_status(fuse, hdr->unique, -ENOENT);
            return;
        }
        oldpath = node_get_path(node, oldbuffer, oldname);

        newparent = lookup_by_inode(fuse, req->newdir);
        if (!newparent) {
            fuse_status(fuse, hdr->unique, -ENOENT);
            return;
        }
        if (newparent == node) {
            /* Special case for renaming a file where destination
             * is same path differing only by case.
             * In this case we don't want to look for a case insensitive match.
             * This allows commands like "mv foo FOO" to work as expected.
             */
            newpath = do_node_get_path(newparent, newbuffer, newname, NO_CASE_SENSITIVE_MATCH);
        } else {
            newpath = node_get_path(newparent, newbuffer, newname);
        }

        if (!remove_child(node, target->nid)) {
            ERROR("RENAME remove_child not found");
            fuse_status(fuse, hdr->unique, -ENOENT);
            return;
        }
        if (!rename_node(target, newname)) {
            fuse_status(fuse, hdr->unique, -ENOMEM);
            return;
        }
        add_node_to_parent(target, newparent);

        res = rename(oldpath, newpath);
        TRACE("RENAME result %d\n", res);

        fuse_status(fuse, hdr->unique, res ? -errno : 0);
        return;
    }

//    case FUSE_LINK:        
    case FUSE_OPEN: { /* open_in -> open_out */
        const struct fuse_open_in *req = data;
        struct fuse_open_out out;
        char *path, buffer[PATH_BUFFER_SIZE];
        struct handle *h;

        h = malloc(sizeof(*h));
        if (!h) {
            fuse_status(fuse, hdr->unique, -ENOMEM);
            return;
        }

        path = node_get_path(node, buffer, 0);
        TRACE("OPEN %llx '%s' 0%o fh=%p\n", hdr->nodeid, path, req->flags, h);
        h->fd = open(path, req->flags);
        if (h->fd < 0) {
            ERROR("ERROR\n");
            fuse_status(fuse, hdr->unique, -errno);
            free(h);
            return;
        }
        out.fh = ptr_to_id(h);
        out.open_flags = 0;
        out.padding = 0;
        fuse_reply(fuse, hdr->unique, &out, sizeof(out));
        return;
    }

    case FUSE_READ: { /* read_in -> byte[] */
        char buffer[MAX_READ];
        const struct fuse_read_in *req = data;
        struct handle *h = id_to_ptr(req->fh);
        int res;
        TRACE("READ %p(%d) %u@%llu\n", h, h->fd, req->size, req->offset);
        if (req->size > sizeof(buffer)) {
            fuse_status(fuse, hdr->unique, -EINVAL);
            return;
        }
        res = pread64(h->fd, buffer, req->size, req->offset);
        if (res < 0) {
            fuse_status(fuse, hdr->unique, -errno);
            return;
        }
        fuse_reply(fuse, hdr->unique, buffer, res);
        return;
    }

    case FUSE_WRITE: { /* write_in, byte[write_in.size] -> write_out */
        const struct fuse_write_in *req = data;
        const void* buffer = (const __u8*)data + sizeof(*req);
        struct fuse_write_out out;
        struct handle *h = id_to_ptr(req->fh);
        int res;
        TRACE("WRITE %p(%d) %u@%llu\n", h, h->fd, req->size, req->offset);
        res = pwrite64(h->fd, buffer, req->size, req->offset);
        if (res < 0) {
            fuse_status(fuse, hdr->unique, -errno);
            return;
        }
        out.size = res;
        fuse_reply(fuse, hdr->unique, &out, sizeof(out));
        return;
    }

    case FUSE_STATFS: { /* getattr_in -> attr_out */
        struct statfs stat;
        struct fuse_statfs_out out;
        int res;

        TRACE("STATFS\n");

        if (statfs(fuse->root.name, &stat)) {
            fuse_status(fuse, hdr->unique, -errno);
            return;
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
        return;
    }

    case FUSE_RELEASE: { /* release_in -> */
        const struct fuse_release_in *req = data;
        struct handle *h = id_to_ptr(req->fh);
        TRACE("RELEASE %p(%d)\n", h, h->fd);
        close(h->fd);
        free(h);
        fuse_status(fuse, hdr->unique, 0);
        return;
    }

    case FUSE_FSYNC: {
        const struct fuse_fsync_in *req = data;
        int is_data_sync = req->fsync_flags & 1;
        struct handle *h = id_to_ptr(req->fh);
        int res;
        TRACE("FSYNC %p(%d) is_data_sync=%d\n", h, h->fd, is_data_sync);
        res = is_data_sync ? fdatasync(h->fd) : fsync(h->fd);
        if (res < 0) {
            fuse_status(fuse, hdr->unique, -errno);
            return;
        }
        fuse_status(fuse, hdr->unique, 0);
        return;
    }

//    case FUSE_SETXATTR:
//    case FUSE_GETXATTR:
//    case FUSE_LISTXATTR:
//    case FUSE_REMOVEXATTR:
    case FUSE_FLUSH: {
        fuse_status(fuse, hdr->unique, 0);
        return;
    }

    case FUSE_OPENDIR: { /* open_in -> open_out */
        const struct fuse_open_in *req = data;
        struct fuse_open_out out;
        char *path, buffer[PATH_BUFFER_SIZE];
        struct dirhandle *h;

        h = malloc(sizeof(*h));
        if (!h) {
            fuse_status(fuse, hdr->unique, -ENOMEM);
            return;
        }

        path = node_get_path(node, buffer, 0);
        TRACE("OPENDIR %llx '%s'\n", hdr->nodeid, path);
        h->d = opendir(path);
        if (h->d == 0) {
            ERROR("ERROR\n");
            fuse_status(fuse, hdr->unique, -errno);
            free(h);
            return;
        }
        out.fh = ptr_to_id(h);
        fuse_reply(fuse, hdr->unique, &out, sizeof(out));
        return;
    }

    case FUSE_READDIR: {
        const struct fuse_read_in *req = data;
        char buffer[8192];
        struct fuse_dirent *fde = (struct fuse_dirent*) buffer;
        struct dirent *de;
        struct dirhandle *h = id_to_ptr(req->fh);
        TRACE("READDIR %p\n", h);
        if (req->offset == 0) {
            /* rewinddir() might have been called above us, so rewind here too */
            TRACE("calling rewinddir()\n");
            rewinddir(h->d);
        }
        de = readdir(h->d);
        if (!de) {
            fuse_status(fuse, hdr->unique, 0);
            return;
        }
        fde->ino = FUSE_UNKNOWN_INO;
        /* increment the offset so we can detect when rewinddir() seeks back to the beginning */
        fde->off = req->offset + 1;
        fde->type = de->d_type;
        fde->namelen = strlen(de->d_name);
        memcpy(fde->name, de->d_name, fde->namelen + 1);
        fuse_reply(fuse, hdr->unique, fde,
                   FUSE_DIRENT_ALIGN(sizeof(struct fuse_dirent) + fde->namelen));
        return;
    }

    case FUSE_RELEASEDIR: { /* release_in -> */
        const struct fuse_release_in *req = data;
        struct dirhandle *h = id_to_ptr(req->fh);
        TRACE("RELEASEDIR %p\n",h);
        closedir(h->d);
        free(h);
        fuse_status(fuse, hdr->unique, 0);
        return;
    }

//    case FUSE_FSYNCDIR:
    case FUSE_INIT: { /* init_in -> init_out */
        const struct fuse_init_in *req = data;
        struct fuse_init_out out;
        
        TRACE("INIT ver=%d.%d maxread=%d flags=%x\n",
                req->major, req->minor, req->max_readahead, req->flags);

        out.major = FUSE_KERNEL_VERSION;
        out.minor = FUSE_KERNEL_MINOR_VERSION;
        out.max_readahead = req->max_readahead;
        out.flags = FUSE_ATOMIC_O_TRUNC | FUSE_BIG_WRITES;
        out.max_background = 32;
        out.congestion_threshold = 32;
        out.max_write = MAX_WRITE;

        fuse_reply(fuse, hdr->unique, &out, sizeof(out));
        return;
    }

    default: {
        ERROR("NOTIMPL op=%d uniq=%llx nid=%llx\n",
                hdr->opcode, hdr->unique, hdr->nodeid);
        fuse_status(fuse, hdr->unique, -ENOSYS);
        break;
    }
    }
}

void handle_fuse_requests(struct fuse *fuse)
{
    __u8 req[MAX_REQUEST_SIZE];

    for (;;) {
        ssize_t len = read(fuse->fd, req, sizeof(req));
        if (len < 0) {
            if (errno == EINTR)
                continue;
            ERROR("handle_fuse_requests: errno=%d\n", errno);
            return;
        }

        if ((size_t)len < sizeof(struct fuse_in_header)) {
            ERROR("request too short: len=%zu\n", (size_t)len);
            return;
        }

        const struct fuse_in_header *hdr = (void*)req;
        if (hdr->len != (size_t)len) {
            ERROR("malformed header: len=%zu, hdr->len=%u\n", (size_t)len, hdr->len);
            return;
        }

        const void *data = req + sizeof(struct fuse_in_header);
        size_t data_len = len - sizeof(struct fuse_in_header);
        handle_fuse_request(fuse, hdr, data, data_len);
    }
}

static int usage()
{
    ERROR("usage: sdcard <path> <uid> <gid>\n\n");
    return 1;
}

static int run(const char* path, uid_t uid, gid_t gid)
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
    handle_fuse_requests(&fuse);

    /* we do not attempt to umount the file system here because we are no longer
     * running as the root user */
    res = 0;

error:
    close(fd);
    return res;
}

int main(int argc, char **argv)
{
    int fd;
    int res;
    const char *path = NULL;
    uid_t uid = 0;
    gid_t gid = 0;
    int i;

    for (i = 1; i < argc; i++) {
        char* arg = argv[i];
        if (!path)
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

    res = run(path, uid, gid);
    return res < 0 ? 1 : 0;
}
