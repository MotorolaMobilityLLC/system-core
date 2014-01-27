#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sys/limits.h>
#include <sys/stat.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <fcntl.h>

/* BEGIN Motorola, wljv10, IKSECURITY-322 */
enum {
  RECURSIVE_OPT = CHAR_MAX + 1,
  HELP_OPT
};

static const char chmod_optstr[] = "hRL";
struct option chmod_long_opt[] =
  {
    {"recursive", no_argument,	NULL, RECURSIVE_OPT},
    {"help",      no_argument,  NULL, HELP_OPT},
    {NULL,        no_argument,  NULL, 0}
  };

static int safe_chmod(char* path, int mode, int traverse_links)
{
    struct stat sb;
    int ret = -1;
    int fd;

    if(traverse_links) {
      ret = chmod(path, mode);
    } else {
       if(stat(path, &sb) == 0) {
	 if((S_ISDIR(sb.st_mode)) || (sb.st_nlink == 1)) {
	   fd = open(path, O_RDONLY | O_NOFOLLOW);
	   if (fd < 0) {
	     fd = open(path, O_WRONLY | O_NOFOLLOW);
	   }
           if (fd >= 0) {
	     ret = fchmod(fd,mode);
	     close(fd);
	   }
	 }
       }
    }
    return(ret);
}

void recurse_chmod(char* path, int mode, int traverse_links)
{
/* END IKSECURITY-322 */
    struct dirent *dp;
    DIR *dir = opendir(path);
    if (dir == NULL) {
        // not a directory, carry on
        return;
    }
    char *subpath = malloc(sizeof(char)*PATH_MAX);
    int pathlen = strlen(path);

    while ((dp = readdir(dir)) != NULL) {
        if (strcmp(dp->d_name, ".") == 0 ||
            strcmp(dp->d_name, "..") == 0) continue;

        if (strlen(dp->d_name) + pathlen + 2/*NUL and slash*/ > PATH_MAX) {
            fprintf(stderr, "Invalid path specified: too long\n");
/* BEGIN Motorola, wljv10, IKSECURITY-322 */
	    free(subpath);
	    closedir(dir);
/* END IKSECURITY-322 */
            exit(1);
        }

        strcpy(subpath, path);
        strcat(subpath, "/");
        strcat(subpath, dp->d_name);

        if (safe_chmod(subpath, mode, traverse_links) < 0) {
            fprintf(stderr, "Unable to chmod %s: %s\n", subpath, strerror(errno));
/* BEGIN Motorola, wljv10, IKSECURITY-322 */
            free(subpath);
            closedir(dir);
/* END IKSECURITY-322 */
            exit(1);
        }
/* BEGIN Motorola, wljv10, IKSECURITY-322 */
        recurse_chmod(subpath, mode, traverse_links);
/* END IKSECURITY-322 */
    }
    free(subpath);
    closedir(dir);
}

static int usage()
{
    fprintf(stderr, "Usage: chmod [OPTION] <MODE> <FILE>\n");
    fprintf(stderr, "  -R, --recursive         change files and directories recursively\n");
/* BEGIN Motorola, wljv10, IKSECURITY-322 */
    fprintf(stderr, "  -L,                     Traverse links (default is to not traverse)\n");
    fprintf(stderr, "  -h,                     Do not traverse links (default)\n");
    fprintf(stderr, "  --help                  display this help and exit\n");
/* END IKSECURITY-322 */
    return 10;
}

int chmod_main(int argc, char **argv)
{
    int i;
/* BEGIN Motorola, wljv10, IKSECURITY-322 */
    int c;
    int recursive = 0;
    int traverse_links = 0;
    int index;

    while (((c = getopt_long(argc, argv, chmod_optstr, chmod_long_opt, NULL)) != -1)) 
    {
      switch (c) {
      case 'R':
      case RECURSIVE_OPT:
	recursive = 1;
	break;
      case 'L':
	traverse_links = 1;
	break;
      case 'h':
	traverse_links = 0;
	break;

      case HELP_OPT:
        usage();
        break;
      case '?':
      default:
	usage();
	return EXIT_FAILURE;
      }
    }
    index = optind;
    if (argc - index != 2) {
        return usage();
    }
    argc -= index;
    argv += index;

    int mode = 0;
    const char* s = argv[0];
/* END IKSECURITY-322 */
    while (*s) {
        if (*s >= '0' && *s <= '7') {
            mode = (mode<<3) | (*s-'0');
        }
        else {
	  fprintf(stderr, "Bad mode\n");
            return 10;
        }
        s++;
    }

    for (i = 1; i < argc; i++) {
/* BEGIN Motorola, wljv10, IKSECURITY-322 */
      if (safe_chmod(argv[i], mode, traverse_links) < 0) {
/* ENDIKSECURITY-322 */
            fprintf(stderr, "Unable to chmod %s: %s\n", argv[i], strerror(errno));
            return 10;
        }
        if (recursive) {
/* BEGIN Motorola, wljv10, IKSECURITY-322 */
	  recurse_chmod(argv[i], mode, traverse_links);
/* END IKSECURITY-322 */
        }
    }
    return 0;
}

