#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>

#include <unistd.h>
#include <time.h>

/* BEGIN Motorola, wljv10, IKSECURITY-322 */
static int usage()
{
     fprintf(stderr, "Usage: chown [OPTION] <USER>[:GROUP] <FILE1> [FILE2] ...\n");
     fprintf(stderr, "  -L,  Traverse links (default is to not traverse)\n");
     return 10;
}

static int safe_chown(char *path, uid_t owner, gid_t group, int traverse_links)
{
    struct stat sb;
    int ret = -1;
    int fd;

    if(traverse_links) {
      ret = chown(path, owner, group);
    } else {
       if(stat(path, &sb) == 0) {
	 if((S_ISDIR(sb.st_mode)) || (sb.st_nlink == 1)) {
	   fd = open(path, O_RDONLY | O_NOFOLLOW);
	   if (fd < 0) {
	     fd = open(path, O_WRONLY | O_NOFOLLOW);
	   }
           if (fd >= 0) {
	     ret = fchown(fd,owner,group);
	     close(fd);
	   }
	 }
       }
    }
    return(ret);
}
/* END IKSECURITY-322 */

int chown_main(int argc, char **argv)
{
    int i;

    if(argc < 3) {
/* BEGIN Motorola, wljv10, IKSECURITY-322 */
        return usage();
    }

    int traverse_links = (strcmp(argv[1], "-L") == 0 ? 1 : 0);

    if (traverse_links && argc < 4) {
        return usage();
    }

    if (traverse_links) {
        argc--;
        argv++;
/* END IKSECURITY-322 */
    }

    // Copy argv[1] to 'user' so we can truncate it at the period
    // if a group id specified.
    char user[32];
    char *group = NULL;
    strncpy(user, argv[1], sizeof(user));
    if ((group = strchr(user, ':')) != NULL) {
        *group++ = '\0';
    } else if ((group = strchr(user, '.')) != NULL) {
        *group++ = '\0';
    }

    // Lookup uid (and gid if specified)
    struct passwd *pw;
    struct group *grp = NULL;
    uid_t uid;
    gid_t gid = -1; // passing -1 to chown preserves current group

    pw = getpwnam(user);
    if (pw != NULL) {
        uid = pw->pw_uid;
    } else {
        char* endptr;
        uid = (int) strtoul(user, &endptr, 0);
        if (endptr == user) {  // no conversion
          fprintf(stderr, "No such user '%s'\n", user);
          return 10;
        }
    }

    if (group != NULL) {
        grp = getgrnam(group);
        if (grp != NULL) {
            gid = grp->gr_gid;
        } else {
            char* endptr;
            gid = (int) strtoul(group, &endptr, 0);
            if (endptr == group) {  // no conversion
                fprintf(stderr, "No such group '%s'\n", group);
                return 10;
            }
        }
    }

    for (i = 2; i < argc; i++) {
/* BEGIN Motorola, wljv10, IKSECURITY-322 */
      if (safe_chown(argv[i], uid, gid, traverse_links) < 0) {
/* END IKSECURITY-322 */
            fprintf(stderr, "Unable to chown %s: %s\n", argv[i], strerror(errno));
            return 10;
      }
    }

    return 0;
}
