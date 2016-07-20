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

#define LOG_TAG "sdcard"

#include "fuse.h"

/* FUSE_CANONICAL_PATH is not currently upstreamed */
#define FUSE_CANONICAL_PATH 2016

#define PROP_SDCARDFS_DEVICE "ro.sys.sdcardfs"
#define PROP_SDCARDFS_USER "persist.sys.sdcardfs"

#define FUSE_UNKNOWN_INO 0xffffffff

/* Pseudo-error constant used to indicate that no fuse status is needed
 * or that a reply has already been written. */
#define NO_STATUS 1

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
static ssize_t get_node_path_locked(struct node* node, char* buf, size_t bufsize) {
    const char* name;
    size_t namelen;
    if (node->graft_path) {
        name = node->graft_path;
        namelen = node->graft_pathlen;
    } else if (node->actual_name) {
        name = node->actual_name;
        namelen = node->namelen;
    } else {
        name = node->name;
        namelen = node->namelen;
    }

    if (bufsize < namelen + 1) {
        return -1;
    }

    ssize_t pathlen = 0;
    if (node->parent && node->graft_path == NULL) {
        pathlen = get_node_path_locked(node->parent, buf, bufsize - namelen - 1);
        if (pathlen < 0) {
            return -1;
        }
        buf[pathlen++] = '/';
    }

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
            ERROR("opendir %s failed: %s\n", path, strerror(errno));
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

static void attr_from_stat(struct fuse* fuse, struct fuse_attr *attr,
        const struct stat *s, const struct node* node) {
    attr->ino = node->ino;
    attr->size = s->st_size;
    attr->blocks = s->st_blocks;
    attr->atime = s->st_atim.tv_sec;
    attr->mtime = s->st_mtim.tv_sec;
    attr->ctime = s->st_ctim.tv_sec;
    attr->atimensec = s->st_atim.tv_nsec;
    attr->mtimensec = s->st_mtim.tv_nsec;
    attr->ctimensec = s->st_ctim.tv_nsec;
    attr->mode = s->st_mode;
    attr->nlink = s->st_nlink;

    attr->uid = node->uid;

    if (fuse->gid == AID_SDCARD_RW) {
        /* As an optimization, certain trusted system components only run
         * as owner but operate across all users. Since we're now handing
         * out the sdcard_rw GID only to trusted apps, we're okay relaxing
         * the user boundary enforcement for the default view. The UIDs
         * assigned to app directories are still multiuser aware. */
        attr->gid = AID_SDCARD_RW;
    } else {
        attr->gid = multiuser_get_uid(node->userid, fuse->gid);
    }

    int visible_mode = 0775 & ~fuse->mask;
    if (node->perm == PERM_PRE_ROOT) {
        /* Top of multi-user view should always be visible to ensure
         * secondary users can traverse inside. */
        visible_mode = 0711;
    } else if (node->under_android) {
        /* Block "other" access to Android directories, since only apps
         * belonging to a specific user should be in there; we still
         * leave +x open for the default view. */
        if (fuse->gid == AID_SDCARD_RW) {
            visible_mode = visible_mode & ~0006;
        } else {
            visible_mode = visible_mode & ~0007;
        }
    }
    int owner_mode = s->st_mode & 0700;
    int filtered_mode = visible_mode & (owner_mode | (owner_mode >> 3) | (owner_mode >> 6));
    attr->mode = (attr->mode & S_IFMT) | filtered_mode;
}

static int touch(char* path, mode_t mode) {
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, mode);
    if (fd == -1) {
        if (errno == EEXIST) {
            return 0;
        } else {
            ERROR("Failed to open(%s): %s\n", path, strerror(errno));
            return -1;
        }
    }
    close(fd);
    return 0;
}

static void derive_permissions_locked(struct fuse* fuse, struct node *parent,
        struct node *node) {
    appid_t appid;

    /* By default, each node inherits from its parent */
    node->perm = PERM_INHERIT;
    node->userid = parent->userid;
    node->uid = parent->uid;
    node->under_android = parent->under_android;

    /* Derive custom permissions based on parent and current node */
    switch (parent->perm) {
    case PERM_INHERIT:
        /* Already inherited above */
        break;
    case PERM_PRE_ROOT:
        /* Legacy internal layout places users at top level */
        node->perm = PERM_ROOT;
        node->userid = strtoul(node->name, NULL, 10);
        break;
    case PERM_ROOT:
        /* Assume masked off by default. */
        if (!strcasecmp(node->name, "Android")) {
            /* App-specific directories inside; let anyone traverse */
            node->perm = PERM_ANDROID;
            node->under_android = true;
        }
        break;
    case PERM_ANDROID:
        if (!strcasecmp(node->name, "data")) {
            /* App-specific directories inside; let anyone traverse */
            node->perm = PERM_ANDROID_DATA;
        } else if (!strcasecmp(node->name, "obb")) {
            /* App-specific directories inside; let anyone traverse */
            node->perm = PERM_ANDROID_OBB;
            /* Single OBB directory is always shared */
            node->graft_path = fuse->global->obb_path;
            node->graft_pathlen = strlen(fuse->global->obb_path);
        } else if (!strcasecmp(node->name, "media")) {
            /* App-specific directories inside; let anyone traverse */
            node->perm = PERM_ANDROID_MEDIA;
        }
        break;
    case PERM_ANDROID_DATA:
    case PERM_ANDROID_OBB:
    case PERM_ANDROID_MEDIA:
        const auto& iter = fuse->global->package_to_appid->find(node->name);
        if (iter != fuse->global->package_to_appid->end()) {
            appid = iter->second;
            node->uid = multiuser_get_uid(parent->userid, appid);
        }
        break;
    }
}

void derive_permissions_recursive_locked(struct fuse* fuse, struct node *parent) {
    struct node *node;
    for (node = parent->child; node; node = node->next) {
        derive_permissions_locked(fuse, parent, node);
        if (node->child) {
            derive_permissions_recursive_locked(fuse, node);
        }
    }
}

/* Kernel has already enforced everything we returned through
 * derive_permissions_locked(), so this is used to lock down access
 * even further, such as enforcing that apps hold sdcard_rw. */
static bool check_caller_access_to_name(struct fuse* fuse,
        const struct fuse_in_header *hdr, const struct node* parent_node,
        const char* name, int mode) {
    /* Always block security-sensitive files at root */
    if (parent_node && parent_node->perm == PERM_ROOT) {
        if (!strcasecmp(name, "autorun.inf")
                || !strcasecmp(name, ".android_secure")
                || !strcasecmp(name, "android_secure")) {
            return false;
        }
    }

    /* Root always has access; access for any other UIDs should always
     * be controlled through packages.list. */
    if (hdr->uid == 0) {
        return true;
    }

    /* No extra permissions to enforce */
    return true;
}

static bool check_caller_access_to_node(struct fuse* fuse,
        const struct fuse_in_header *hdr, const struct node* node, int mode) {
    return check_caller_access_to_name(fuse, hdr, node->parent, node->name, mode);
}

struct node *create_node_locked(struct fuse* fuse,
        struct node *parent, const char *name, const char* actual_name)
{
    struct node *node;
    size_t namelen = strlen(name);

    // Detect overflows in the inode counter. "4 billion nodes should be enough
    // for everybody".
    if (fuse->global->inode_ctr == 0) {
        ERROR("No more inode numbers available");
        return NULL;
    }

    node = static_cast<struct node*>(calloc(1, sizeof(struct node)));
    if (!node) {
        return NULL;
    }
    node->name = static_cast<char*>(malloc(namelen + 1));
    if (!node->name) {
        free(node);
        return NULL;
    }
    memcpy(node->name, name, namelen + 1);
    if (strcmp(name, actual_name)) {
        node->actual_name = static_cast<char*>(malloc(namelen + 1));
        if (!node->actual_name) {
            free(node->name);
            free(node);
            return NULL;
        }
        memcpy(node->actual_name, actual_name, namelen + 1);
    }
    node->namelen = namelen;
    node->nid = ptr_to_id(node);
    node->ino = fuse->global->inode_ctr++;
    node->gen = fuse->global->next_generation++;

    node->deleted = false;

    derive_permissions_locked(fuse, parent, node);
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
        char* new_name = static_cast<char*>(realloc(node->name, namelen + 1));
        if (!new_name) {
            return -ENOMEM;
        }
        node->name = new_name;
        if (need_actual_name && node->actual_name) {
            char* new_actual_name = static_cast<char*>(realloc(node->actual_name, namelen + 1));
            if (!new_actual_name) {
                return -ENOMEM;
            }
            node->actual_name = new_actual_name;
        }
    }

    /* update the name, taking care to allocate storage before overwriting the old name */
    if (need_actual_name) {
        if (!node->actual_name) {
            node->actual_name = static_cast<char*>(malloc(namelen + 1));
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
        return &fuse->global->root;
    } else {
        return static_cast<struct node*>(id_to_ptr(nid));
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
        if (!strcmp(name, node->name) && !node->deleted) {
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

    pthread_mutex_lock(&fuse->global->lock);
    node = acquire_or_create_child_locked(fuse, parent, name, actual_name);
    if (!node) {
        pthread_mutex_unlock(&fuse->global->lock);
        return -ENOMEM;
    }
    memset(&out, 0, sizeof(out));
    attr_from_stat(fuse, &out.attr, &s, node);
    out.attr_valid = 10;
    out.entry_valid = 10;
    out.nodeid = node->nid;
    out.generation = node->gen;
    pthread_mutex_unlock(&fuse->global->lock);
    fuse_reply(fuse, unique, &out, sizeof(out));
    return NO_STATUS;
}

static int fuse_reply_attr(struct fuse* fuse, __u64 unique, const struct node* node,
        const char* path)
{
    struct fuse_attr_out out;
    struct stat s;

    if (lstat(path, &s) < 0) {
        return -errno;
    }
    memset(&out, 0, sizeof(out));
    attr_from_stat(fuse, &out.attr, &s, node);
    out.attr_valid = 10;
    fuse_reply(fuse, unique, &out, sizeof(out));
    return NO_STATUS;
}

static void fuse_notify_delete(struct fuse* fuse, const __u64 parent,
        const __u64 child, const char* name) {
    struct fuse_out_header hdr;
    struct fuse_notify_delete_out data;
    struct iovec vec[3];
    size_t namelen = strlen(name);
    int res;

    hdr.len = sizeof(hdr) + sizeof(data) + namelen + 1;
    hdr.error = FUSE_NOTIFY_DELETE;
    hdr.unique = 0;

    data.parent = parent;
    data.child = child;
    data.namelen = namelen;
    data.padding = 0;

    vec[0].iov_base = &hdr;
    vec[0].iov_len = sizeof(hdr);
    vec[1].iov_base = &data;
    vec[1].iov_len = sizeof(data);
    vec[2].iov_base = (void*) name;
    vec[2].iov_len = namelen + 1;

    res = writev(fuse->fd, vec, 3);
    /* Ignore ENOENT, since other views may not have seen the entry */
    if (res < 0 && errno != ENOENT) {
        ERROR("*** NOTIFY FAILED *** %d\n", errno);
    }
}

static int handle_lookup(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header *hdr, const char* name)
{
    struct node* parent_node;
    char parent_path[PATH_MAX];
    char child_path[PATH_MAX];
    const char* actual_name;

    pthread_mutex_lock(&fuse->global->lock);
    parent_node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid,
            parent_path, sizeof(parent_path));
    TRACE("[%d] LOOKUP %s @ %" PRIx64 " (%s)\n", handler->token, name, hdr->nodeid,
        parent_node ? parent_node->name : "?");
    pthread_mutex_unlock(&fuse->global->lock);

    if (!parent_node || !(actual_name = find_file_within(parent_path, name,
            child_path, sizeof(child_path), 1))) {
        return -ENOENT;
    }
    if (!check_caller_access_to_name(fuse, hdr, parent_node, name, R_OK)) {
        return -EACCES;
    }

    return fuse_reply_entry(fuse, hdr->unique, parent_node, name, actual_name, child_path);
}

static int handle_forget(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header *hdr, const struct fuse_forget_in *req)
{
    struct node* node;

    pthread_mutex_lock(&fuse->global->lock);
    node = lookup_node_by_id_locked(fuse, hdr->nodeid);
    TRACE("[%d] FORGET #%" PRIu64 " @ %" PRIx64 " (%s)\n", handler->token, req->nlookup,
            hdr->nodeid, node ? node->name : "?");
    if (node) {
        __u64 n = req->nlookup;
        while (n) {
            n--;
            release_node_locked(node);
        }
    }
    pthread_mutex_unlock(&fuse->global->lock);
    return NO_STATUS; /* no reply */
}

static int handle_getattr(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header *hdr, const struct fuse_getattr_in *req)
{
    struct node* node;
    char path[PATH_MAX];

    pthread_mutex_lock(&fuse->global->lock);
    node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid, path, sizeof(path));
    TRACE("[%d] GETATTR flags=%x fh=%" PRIx64 " @ %" PRIx64 " (%s)\n", handler->token,
            req->getattr_flags, req->fh, hdr->nodeid, node ? node->name : "?");
    pthread_mutex_unlock(&fuse->global->lock);

    if (!node) {
        return -ENOENT;
    }
    if (!check_caller_access_to_node(fuse, hdr, node, R_OK)) {
        return -EACCES;
    }

    return fuse_reply_attr(fuse, hdr->unique, node, path);
}

static int handle_setattr(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header *hdr, const struct fuse_setattr_in *req)
{
    struct node* node;
    char path[PATH_MAX];
    struct timespec times[2];

    pthread_mutex_lock(&fuse->global->lock);
    node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid, path, sizeof(path));
    TRACE("[%d] SETATTR fh=%" PRIx64 " valid=%x @ %" PRIx64 " (%s)\n", handler->token,
            req->fh, req->valid, hdr->nodeid, node ? node->name : "?");
    pthread_mutex_unlock(&fuse->global->lock);

    if (!node) {
        return -ENOENT;
    }

    if (!(req->valid & FATTR_FH) &&
            !check_caller_access_to_node(fuse, hdr, node, W_OK)) {
        return -EACCES;
    }

    /* XXX: incomplete implementation on purpose.
     * chmod/chown should NEVER be implemented.*/

    if ((req->valid & FATTR_SIZE) && truncate64(path, req->size) < 0) {
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
    return fuse_reply_attr(fuse, hdr->unique, node, path);
}

static int handle_mknod(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const struct fuse_mknod_in* req, const char* name)
{
    struct node* parent_node;
    char parent_path[PATH_MAX];
    char child_path[PATH_MAX];
    const char* actual_name;

    pthread_mutex_lock(&fuse->global->lock);
    parent_node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid,
            parent_path, sizeof(parent_path));
    TRACE("[%d] MKNOD %s 0%o @ %" PRIx64 " (%s)\n", handler->token,
            name, req->mode, hdr->nodeid, parent_node ? parent_node->name : "?");
    pthread_mutex_unlock(&fuse->global->lock);

    if (!parent_node || !(actual_name = find_file_within(parent_path, name,
            child_path, sizeof(child_path), 1))) {
        return -ENOENT;
    }
    if (!check_caller_access_to_name(fuse, hdr, parent_node, name, W_OK)) {
        return -EACCES;
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

    pthread_mutex_lock(&fuse->global->lock);
    parent_node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid,
            parent_path, sizeof(parent_path));
    TRACE("[%d] MKDIR %s 0%o @ %" PRIx64 " (%s)\n", handler->token,
            name, req->mode, hdr->nodeid, parent_node ? parent_node->name : "?");
    pthread_mutex_unlock(&fuse->global->lock);

    if (!parent_node || !(actual_name = find_file_within(parent_path, name,
            child_path, sizeof(child_path), 1))) {
        return -ENOENT;
    }
    if (!check_caller_access_to_name(fuse, hdr, parent_node, name, W_OK)) {
        return -EACCES;
    }
    __u32 mode = (req->mode & (~0777)) | 0775;
    if (mkdir(child_path, mode) < 0) {
        return -errno;
    }

    /* When creating /Android/data and /Android/obb, mark them as .nomedia */
    if (parent_node->perm == PERM_ANDROID && !strcasecmp(name, "data")) {
        char nomedia[PATH_MAX];
        snprintf(nomedia, PATH_MAX, "%s/.nomedia", child_path);
        if (touch(nomedia, 0664) != 0) {
            ERROR("Failed to touch(%s): %s\n", nomedia, strerror(errno));
            return -ENOENT;
        }
    }
    if (parent_node->perm == PERM_ANDROID && !strcasecmp(name, "obb")) {
        char nomedia[PATH_MAX];
        snprintf(nomedia, PATH_MAX, "%s/.nomedia", fuse->global->obb_path);
        if (touch(nomedia, 0664) != 0) {
            ERROR("Failed to touch(%s): %s\n", nomedia, strerror(errno));
            return -ENOENT;
        }
    }

    return fuse_reply_entry(fuse, hdr->unique, parent_node, name, actual_name, child_path);
}

static int handle_unlink(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const char* name)
{
    struct node* parent_node;
    struct node* child_node;
    char parent_path[PATH_MAX];
    char child_path[PATH_MAX];

    pthread_mutex_lock(&fuse->global->lock);
    parent_node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid,
            parent_path, sizeof(parent_path));
    TRACE("[%d] UNLINK %s @ %" PRIx64 " (%s)\n", handler->token,
            name, hdr->nodeid, parent_node ? parent_node->name : "?");
    pthread_mutex_unlock(&fuse->global->lock);

    if (!parent_node || !find_file_within(parent_path, name,
            child_path, sizeof(child_path), 1)) {
        return -ENOENT;
    }
    if (!check_caller_access_to_name(fuse, hdr, parent_node, name, W_OK)) {
        return -EACCES;
    }
    if (unlink(child_path) < 0) {
        return -errno;
    }
    pthread_mutex_lock(&fuse->global->lock);
    child_node = lookup_child_by_name_locked(parent_node, name);
    if (child_node) {
        child_node->deleted = true;
    }
    pthread_mutex_unlock(&fuse->global->lock);
    if (parent_node && child_node) {
        /* Tell all other views that node is gone */
        TRACE("[%d] fuse_notify_delete parent=%" PRIx64 ", child=%" PRIx64 ", name=%s\n",
                handler->token, (uint64_t) parent_node->nid, (uint64_t) child_node->nid, name);
        if (fuse != fuse->global->fuse_default) {
            fuse_notify_delete(fuse->global->fuse_default, parent_node->nid, child_node->nid, name);
        }
        if (fuse != fuse->global->fuse_read) {
            fuse_notify_delete(fuse->global->fuse_read, parent_node->nid, child_node->nid, name);
        }
        if (fuse != fuse->global->fuse_write) {
            fuse_notify_delete(fuse->global->fuse_write, parent_node->nid, child_node->nid, name);
        }
    }
    return 0;
}

static int handle_rmdir(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const char* name)
{
    struct node* child_node;
    struct node* parent_node;
    char parent_path[PATH_MAX];
    char child_path[PATH_MAX];

    pthread_mutex_lock(&fuse->global->lock);
    parent_node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid,
            parent_path, sizeof(parent_path));
    TRACE("[%d] RMDIR %s @ %" PRIx64 " (%s)\n", handler->token,
            name, hdr->nodeid, parent_node ? parent_node->name : "?");
    pthread_mutex_unlock(&fuse->global->lock);

    if (!parent_node || !find_file_within(parent_path, name,
            child_path, sizeof(child_path), 1)) {
        return -ENOENT;
    }
    if (!check_caller_access_to_name(fuse, hdr, parent_node, name, W_OK)) {
        return -EACCES;
    }
    if (rmdir(child_path) < 0) {
        return -errno;
    }
    pthread_mutex_lock(&fuse->global->lock);
    child_node = lookup_child_by_name_locked(parent_node, name);
    if (child_node) {
        child_node->deleted = true;
    }
    pthread_mutex_unlock(&fuse->global->lock);
    if (parent_node && child_node) {
        /* Tell all other views that node is gone */
        TRACE("[%d] fuse_notify_delete parent=%" PRIx64 ", child=%" PRIx64 ", name=%s\n",
                handler->token, (uint64_t) parent_node->nid, (uint64_t) child_node->nid, name);
        if (fuse != fuse->global->fuse_default) {
            fuse_notify_delete(fuse->global->fuse_default, parent_node->nid, child_node->nid, name);
        }
        if (fuse != fuse->global->fuse_read) {
            fuse_notify_delete(fuse->global->fuse_read, parent_node->nid, child_node->nid, name);
        }
        if (fuse != fuse->global->fuse_write) {
            fuse_notify_delete(fuse->global->fuse_write, parent_node->nid, child_node->nid, name);
        }
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
    int search;
    int res;

    pthread_mutex_lock(&fuse->global->lock);
    old_parent_node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid,
            old_parent_path, sizeof(old_parent_path));
    new_parent_node = lookup_node_and_path_by_id_locked(fuse, req->newdir,
            new_parent_path, sizeof(new_parent_path));
    TRACE("[%d] RENAME %s->%s @ %" PRIx64 " (%s) -> %" PRIx64 " (%s)\n", handler->token,
            old_name, new_name,
            hdr->nodeid, old_parent_node ? old_parent_node->name : "?",
            req->newdir, new_parent_node ? new_parent_node->name : "?");
    if (!old_parent_node || !new_parent_node) {
        res = -ENOENT;
        goto lookup_error;
    }
    if (!check_caller_access_to_name(fuse, hdr, old_parent_node, old_name, W_OK)) {
        res = -EACCES;
        goto lookup_error;
    }
    if (!check_caller_access_to_name(fuse, hdr, new_parent_node, new_name, W_OK)) {
        res = -EACCES;
        goto lookup_error;
    }
    child_node = lookup_child_by_name_locked(old_parent_node, old_name);
    if (!child_node || get_node_path_locked(child_node,
            old_child_path, sizeof(old_child_path)) < 0) {
        res = -ENOENT;
        goto lookup_error;
    }
    acquire_node_locked(child_node);
    pthread_mutex_unlock(&fuse->global->lock);

    /* Special case for renaming a file where destination is same path
     * differing only by case.  In this case we don't want to look for a case
     * insensitive match.  This allows commands like "mv foo FOO" to work as expected.
     */
    search = old_parent_node != new_parent_node
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

    pthread_mutex_lock(&fuse->global->lock);
    res = rename_node_locked(child_node, new_name, new_actual_name);
    if (!res) {
        remove_node_from_parent_locked(child_node);
        derive_permissions_locked(fuse, new_parent_node, child_node);
        derive_permissions_recursive_locked(fuse, child_node);
        add_node_to_parent_locked(child_node, new_parent_node);
    }
    goto done;

io_error:
    pthread_mutex_lock(&fuse->global->lock);
done:
    release_node_locked(child_node);
lookup_error:
    pthread_mutex_unlock(&fuse->global->lock);
    return res;
}

static int open_flags_to_access_mode(int open_flags) {
    if ((open_flags & O_ACCMODE) == O_RDONLY) {
        return R_OK;
    } else if ((open_flags & O_ACCMODE) == O_WRONLY) {
        return W_OK;
    } else {
        /* Probably O_RDRW, but treat as default to be safe */
        return R_OK | W_OK;
    }
}

static int handle_open(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const struct fuse_open_in* req)
{
    struct node* node;
    char path[PATH_MAX];
    struct fuse_open_out out;
    struct handle *h;

    pthread_mutex_lock(&fuse->global->lock);
    node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid, path, sizeof(path));
    TRACE("[%d] OPEN 0%o @ %" PRIx64 " (%s)\n", handler->token,
            req->flags, hdr->nodeid, node ? node->name : "?");
    pthread_mutex_unlock(&fuse->global->lock);

    if (!node) {
        return -ENOENT;
    }
    if (!check_caller_access_to_node(fuse, hdr, node,
            open_flags_to_access_mode(req->flags))) {
        return -EACCES;
    }
    h = static_cast<struct handle*>(malloc(sizeof(*h)));
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
    struct handle *h = static_cast<struct handle*>(id_to_ptr(req->fh));
    __u64 unique = hdr->unique;
    __u32 size = req->size;
    __u64 offset = req->offset;
    int res;
    __u8 *read_buffer = (__u8 *) ((uintptr_t)(handler->read_buffer + PAGE_SIZE) & ~((uintptr_t)PAGE_SIZE-1));

    /* Don't access any other fields of hdr or req beyond this point, the read buffer
     * overlaps the request buffer and will clobber data in the request.  This
     * saves us 128KB per request handler thread at the cost of this scary comment. */

    TRACE("[%d] READ %p(%d) %u@%" PRIu64 "\n", handler->token,
            h, h->fd, size, (uint64_t) offset);
    if (size > MAX_READ) {
        return -EINVAL;
    }
    res = pread64(h->fd, read_buffer, size, offset);
    if (res < 0) {
        return -errno;
    }
    fuse_reply(fuse, unique, read_buffer, res);
    return NO_STATUS;
}

static int handle_write(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const struct fuse_write_in* req,
        const void* buffer)
{
    struct fuse_write_out out;
    struct handle *h = static_cast<struct handle*>(id_to_ptr(req->fh));
    int res;
    __u8 aligned_buffer[req->size] __attribute__((__aligned__(PAGE_SIZE)));

    if (req->flags & O_DIRECT) {
        memcpy(aligned_buffer, buffer, req->size);
        buffer = (const __u8*) aligned_buffer;
    }

    TRACE("[%d] WRITE %p(%d) %u@%" PRIu64 "\n", handler->token,
            h, h->fd, req->size, req->offset);
    res = pwrite64(h->fd, buffer, req->size, req->offset);
    if (res < 0) {
        return -errno;
    }
    out.size = res;
    out.padding = 0;
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

    pthread_mutex_lock(&fuse->global->lock);
    TRACE("[%d] STATFS\n", handler->token);
    res = get_node_path_locked(&fuse->global->root, path, sizeof(path));
    pthread_mutex_unlock(&fuse->global->lock);
    if (res < 0) {
        return -ENOENT;
    }
    if (statfs(fuse->global->root.name, &stat) < 0) {
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
    struct handle *h = static_cast<struct handle*>(id_to_ptr(req->fh));

    TRACE("[%d] RELEASE %p(%d)\n", handler->token, h, h->fd);
    close(h->fd);
    free(h);
    return 0;
}

static int handle_fsync(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const struct fuse_fsync_in* req)
{
    bool is_dir = (hdr->opcode == FUSE_FSYNCDIR);
    bool is_data_sync = req->fsync_flags & 1;

    int fd = -1;
    if (is_dir) {
      struct dirhandle *dh = static_cast<struct dirhandle*>(id_to_ptr(req->fh));
      fd = dirfd(dh->d);
    } else {
      struct handle *h = static_cast<struct handle*>(id_to_ptr(req->fh));
      fd = h->fd;
    }

    TRACE("[%d] %s %p(%d) is_data_sync=%d\n", handler->token,
            is_dir ? "FSYNCDIR" : "FSYNC",
            static_cast<struct node*>(id_to_ptr(req->fh)), fd, is_data_sync);
    int res = is_data_sync ? fdatasync(fd) : fsync(fd);
    if (res == -1) {
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

    pthread_mutex_lock(&fuse->global->lock);
    node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid, path, sizeof(path));
    TRACE("[%d] OPENDIR @ %" PRIx64 " (%s)\n", handler->token,
            hdr->nodeid, node ? node->name : "?");
    pthread_mutex_unlock(&fuse->global->lock);

    if (!node) {
        return -ENOENT;
    }
    if (!check_caller_access_to_node(fuse, hdr, node, R_OK)) {
        return -EACCES;
    }
    h = static_cast<struct dirhandle*>(malloc(sizeof(*h)));
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
    out.open_flags = 0;
    out.padding = 0;
    fuse_reply(fuse, hdr->unique, &out, sizeof(out));
    return NO_STATUS;
}

static int handle_readdir(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const struct fuse_read_in* req)
{
    char buffer[8192];
    struct fuse_dirent *fde = (struct fuse_dirent*) buffer;
    struct dirent *de;
    struct dirhandle *h = static_cast<struct dirhandle*>(id_to_ptr(req->fh));

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
    struct dirhandle *h = static_cast<struct dirhandle*>(id_to_ptr(req->fh));

    TRACE("[%d] RELEASEDIR %p\n", handler->token, h);
    closedir(h->d);
    free(h);
    return 0;
}

static int handle_init(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header* hdr, const struct fuse_init_in* req)
{
    struct fuse_init_out out;
    size_t fuse_struct_size;

    TRACE("[%d] INIT ver=%d.%d maxread=%d flags=%x\n",
            handler->token, req->major, req->minor, req->max_readahead, req->flags);

    /* Kernel 2.6.16 is the first stable kernel with struct fuse_init_out
     * defined (fuse version 7.6). The structure is the same from 7.6 through
     * 7.22. Beginning with 7.23, the structure increased in size and added
     * new parameters.
     */
    if (req->major != FUSE_KERNEL_VERSION || req->minor < 6) {
        ERROR("Fuse kernel version mismatch: Kernel version %d.%d, Expected at least %d.6",
              req->major, req->minor, FUSE_KERNEL_VERSION);
        return -1;
    }

    /* We limit ourselves to 15 because we don't handle BATCH_FORGET yet */
    out.minor = MIN(req->minor, 15);
    fuse_struct_size = sizeof(out);
#if defined(FUSE_COMPAT_22_INIT_OUT_SIZE)
    /* FUSE_KERNEL_VERSION >= 23. */

    /* If the kernel only works on minor revs older than or equal to 22,
     * then use the older structure size since this code only uses the 7.22
     * version of the structure. */
    if (req->minor <= 22) {
        fuse_struct_size = FUSE_COMPAT_22_INIT_OUT_SIZE;
    }
#endif

    out.major = FUSE_KERNEL_VERSION;
    out.max_readahead = req->max_readahead;
    out.flags = FUSE_ATOMIC_O_TRUNC | FUSE_BIG_WRITES;
    out.max_background = 32;
    out.congestion_threshold = 32;
    out.max_write = MAX_WRITE;
    fuse_reply(fuse, hdr->unique, &out, fuse_struct_size);
    return NO_STATUS;
}

static int handle_canonical_path(struct fuse* fuse, struct fuse_handler* handler,
        const struct fuse_in_header *hdr)
{
    struct node* node;
    char path[PATH_MAX];
    int len;

    pthread_mutex_lock(&fuse->global->lock);
    node = lookup_node_and_path_by_id_locked(fuse, hdr->nodeid,
            path, sizeof(path));
    TRACE("[%d] CANONICAL_PATH @ %" PRIx64 " (%s)\n", handler->token, hdr->nodeid,
        node ? node->name : "?");
    pthread_mutex_unlock(&fuse->global->lock);

    if (!node) {
        return -ENOENT;
    }
    if (!check_caller_access_to_node(fuse, hdr, node, R_OK)) {
        return -EACCES;
    }
    len = strlen(path);
    if (len + 1 > PATH_MAX)
        len = PATH_MAX - 1;
    path[PATH_MAX - 1] = 0;
    fuse_reply(fuse, hdr->unique, path, len + 1);
    return NO_STATUS;
}


static int handle_fuse_request(struct fuse *fuse, struct fuse_handler* handler,
        const struct fuse_in_header *hdr, const void *data, size_t data_len)
{
    switch (hdr->opcode) {
    case FUSE_LOOKUP: { /* bytez[] -> entry_out */
        const char *name = static_cast<const char*>(data);
        return handle_lookup(fuse, handler, hdr, name);
    }

    case FUSE_FORGET: {
        const struct fuse_forget_in *req = static_cast<const struct fuse_forget_in*>(data);
        return handle_forget(fuse, handler, hdr, req);
    }

    case FUSE_GETATTR: { /* getattr_in -> attr_out */
        const struct fuse_getattr_in *req = static_cast<const struct fuse_getattr_in*>(data);
        return handle_getattr(fuse, handler, hdr, req);
    }

    case FUSE_SETATTR: { /* setattr_in -> attr_out */
        const struct fuse_setattr_in *req = static_cast<const struct fuse_setattr_in*>(data);
        return handle_setattr(fuse, handler, hdr, req);
    }

//    case FUSE_READLINK:
//    case FUSE_SYMLINK:
    case FUSE_MKNOD: { /* mknod_in, bytez[] -> entry_out */
        const struct fuse_mknod_in *req = static_cast<const struct fuse_mknod_in*>(data);
        const char *name = ((const char*) data) + sizeof(*req);
        return handle_mknod(fuse, handler, hdr, req, name);
    }

    case FUSE_MKDIR: { /* mkdir_in, bytez[] -> entry_out */
        const struct fuse_mkdir_in *req = static_cast<const struct fuse_mkdir_in*>(data);
        const char *name = ((const char*) data) + sizeof(*req);
        return handle_mkdir(fuse, handler, hdr, req, name);
    }

    case FUSE_UNLINK: { /* bytez[] -> */
        const char *name = static_cast<const char*>(data);
        return handle_unlink(fuse, handler, hdr, name);
    }

    case FUSE_RMDIR: { /* bytez[] -> */
        const char *name = static_cast<const char*>(data);
        return handle_rmdir(fuse, handler, hdr, name);
    }

    case FUSE_RENAME: { /* rename_in, oldname, newname ->  */
        const struct fuse_rename_in *req = static_cast<const struct fuse_rename_in*>(data);
        const char *old_name = ((const char*) data) + sizeof(*req);
        const char *new_name = old_name + strlen(old_name) + 1;
        return handle_rename(fuse, handler, hdr, req, old_name, new_name);
    }

//    case FUSE_LINK:
    case FUSE_OPEN: { /* open_in -> open_out */
        const struct fuse_open_in *req = static_cast<const struct fuse_open_in*>(data);
        return handle_open(fuse, handler, hdr, req);
    }

    case FUSE_READ: { /* read_in -> byte[] */
        const struct fuse_read_in *req = static_cast<const struct fuse_read_in*>(data);
        return handle_read(fuse, handler, hdr, req);
    }

    case FUSE_WRITE: { /* write_in, byte[write_in.size] -> write_out */
        const struct fuse_write_in *req = static_cast<const struct fuse_write_in*>(data);
        const void* buffer = (const __u8*)data + sizeof(*req);
        return handle_write(fuse, handler, hdr, req, buffer);
    }

    case FUSE_STATFS: { /* getattr_in -> attr_out */
        return handle_statfs(fuse, handler, hdr);
    }

    case FUSE_RELEASE: { /* release_in -> */
        const struct fuse_release_in *req = static_cast<const struct fuse_release_in*>(data);
        return handle_release(fuse, handler, hdr, req);
    }

    case FUSE_FSYNC:
    case FUSE_FSYNCDIR: {
        const struct fuse_fsync_in *req = static_cast<const struct fuse_fsync_in*>(data);
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
        const struct fuse_open_in *req = static_cast<const struct fuse_open_in*>(data);
        return handle_opendir(fuse, handler, hdr, req);
    }

    case FUSE_READDIR: {
        const struct fuse_read_in *req = static_cast<const struct fuse_read_in*>(data);
        return handle_readdir(fuse, handler, hdr, req);
    }

    case FUSE_RELEASEDIR: { /* release_in -> */
        const struct fuse_release_in *req = static_cast<const struct fuse_release_in*>(data);
        return handle_releasedir(fuse, handler, hdr, req);
    }

    case FUSE_INIT: { /* init_in -> init_out */
        const struct fuse_init_in *req = static_cast<const struct fuse_init_in*>(data);
        return handle_init(fuse, handler, hdr, req);
    }

    case FUSE_CANONICAL_PATH: { /* nodeid -> bytez[] */
        return handle_canonical_path(fuse, handler, hdr);
    }

    default: {
        TRACE("[%d] NOTIMPL op=%d uniq=%" PRIx64 " nid=%" PRIx64 "\n",
                handler->token, hdr->opcode, hdr->unique, hdr->nodeid);
        return -ENOSYS;
    }
    }
}

void handle_fuse_requests(struct fuse_handler* handler)
{
    struct fuse* fuse = handler->fuse;
    for (;;) {
        ssize_t len = TEMP_FAILURE_RETRY(read(fuse->fd,
                handler->request_buffer, sizeof(handler->request_buffer)));
        if (len < 0) {
            if (errno == ENODEV) {
                ERROR("[%d] someone stole our marbles!\n", handler->token);
                exit(2);
            }
            ERROR("[%d] handle_fuse_requests: errno=%d\n", handler->token, errno);
            continue;
        }

        if ((size_t)len < sizeof(struct fuse_in_header)) {
            ERROR("[%d] request too short: len=%zu\n", handler->token, (size_t)len);
            continue;
        }

        const struct fuse_in_header* hdr =
            reinterpret_cast<const struct fuse_in_header*>(handler->request_buffer);
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
