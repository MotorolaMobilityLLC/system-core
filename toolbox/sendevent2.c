// This code is based on toolbox/sendevent command from AOSP
// and has been modified by Motorola to workaround
// performance issues when injecting touch commands.
// -e50097

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
//#include <linux/input.h> // this does not compile
#include <errno.h>

// from <linux/input.h>
struct input_event {
        struct timeval time;
        __u16 type;
        __u16 code;
        __s32 value;
 };

 #define EVIOCGVERSION          _IOR('E', 0x01, int)                    /* getdriver version */
 #define EVIOCGID               _IOR('E', 0x02, struct input_id)        /* getdevice ID */
 #define EVIOCGKEYCODE          _IOR('E', 0x04, int[2])                 /* getkeycode */
 #define EVIOCSKEYCODE          _IOW('E', 0x04, int[2])                 /* setkeycode */
 #define EVIOCGNAME(len)        _IOC(_IOC_READ, 'E', 0x06, len)         /* get device name */
 #define EVIOCGPHYS(len)        _IOC(_IOC_READ, 'E', 0x07, len)         /* get physical location */
 #define EVIOCGUNIQ(len)        _IOC(_IOC_READ, 'E', 0x08, len)         /* get unique identifier */
 #define EVIOCGKEY(len)         _IOC(_IOC_READ, 'E', 0x18, len)         /* get global keystate */
 #define EVIOCGLED(len)         _IOC(_IOC_READ, 'E', 0x19, len)         /* get all LEDs */
 #define EVIOCGSND(len)         _IOC(_IOC_READ, 'E', 0x1a, len)         /* get all sounds status */
 #define EVIOCGSW(len)          _IOC(_IOC_READ, 'E', 0x1b, len)         /* get all switch states */
 #define EVIOCGBIT(ev,len)      _IOC(_IOC_READ, 'E', 0x20 + ev, len)    /* get event bits */
 #define EVIOCGABS(abs)         _IOR('E', 0x40 + abs, struct input_absinfo) /* get abs value/limits */
 #define EVIOCSABS(abs)         _IOW('E', 0xc0 + abs, struct input_absinfo) /* set abs value/limits */
 #define EVIOCSFF               _IOC(_IOC_WRITE, 'E', 0x80, sizeof(struct ff_effect))   /* send a force effect to a force feedback device */
 #define EVIOCRMFF              _IOW('E', 0x81, int)                    /* Erase a force effect */
 #define EVIOCGEFFECTS          _IOR('E', 0x84, int)                    /* Report number of effects playable at the same time */
 #define EVIOCGRAB              _IOW('E', 0x90, int)                    /* Grab/Release device */
 // end <linux/input.h>

int sendevent2_main(int argc, char *argv[])
{
     int fd;
     ssize_t ret;
     int version;
     struct input_event event;

     // Motorola - BEGIN - IKAPP-606 - wqnt78 - 3/10/2010 - PTF enabler
     //
     // Allow automation tools to more closely control event timing byextending
     // sendevent to send multiple events, separated by timeouts (in ms). Note
     // there is no trailing timeout. Sample usage:
     //
     //     sendevent2 device type code value timeout device type code value
     //
     char *device = NULL;
     fd = -1;
     if (argc % 5) { // No trailing timeout
             fprintf(stderr, "use: %s device type code value [ timeout device type code value ] ...\n", argv[0]);
             return 1;
     }

     for (;argc;argv += 5, argc -= 5) {
         if (!device || strcmp(argv[1], device)) {
             if (fd > 0)
                 close(fd);
             device = argv[1];
             fd = open(argv[1], O_RDWR);
             if(fd < 0) {
                 fprintf(stderr, "could not open %s, %s\n", argv[optind], strerror(errno));
                 return 1;
             }

             if (ioctl(fd, EVIOCGVERSION, &version)) {
                 fprintf(stderr, "could not get driver version for %s, %s\n", argv[optind], strerror(errno));
                 close(fd);
                 return 1;
             }
         }

         memset(&event, 0, sizeof(event));
         event.type = atoi(argv[2]);
         event.code = atoi(argv[3]);
         event.value = atoi(argv[4]);
         ret = write(fd, &event, sizeof(event));
         if (ret < (ssize_t)sizeof(event)) {
             fprintf(stderr, "write event failed, %s\n", strerror(errno));
             close(fd);
             return -1;
         }

         if (argc > 5) {
             usleep(1000*atoi(argv[5]));
         }
     }
     if (fd > 0)
         close(fd);
     return 0;
     // Motorola - END - IKAPP-606 - wqnt78 - 3/10/2010 - PTF enabler
}
