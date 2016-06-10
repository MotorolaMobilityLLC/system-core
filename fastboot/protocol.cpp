/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define round_down(a, b) \
    ({ typeof(a) _a = (a); typeof(b) _b = (b); _a - (_a % _b); })

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>

#include <sparse/sparse.h>

#include "fastboot.h"
#include "transport.h"

static char ERROR[128];

#define BULK_SIZE    1024 * 1024

char *fb_get_error(void)
{
    return ERROR;
}

static int check_response(Transport* transport, uint32_t size, char* response) {
    char status[65];

    while (true) {
        int r = transport->Read(status, 64);
        if (r < 0) {
            sprintf(ERROR, "status read failed (%s)", strerror(errno));
            transport->Close();
            return -1;
        }
        status[r] = 0;

        if (r < 4) {
            sprintf(ERROR, "status malformed (%d bytes)", r);
            transport->Close();
            return -1;
        }

        if (!memcmp(status, "INFO", 4)) {
            fprintf(stderr,"(bootloader) %s\n", status + 4);
            continue;
        }

        if (!memcmp(status, "OKAY", 4)) {
            if (response) {
                strcpy(response, (char*) status + 4);
            }
            return 0;
        }

        if (!memcmp(status, "FAIL", 4)) {
            if (r > 4) {
                sprintf(ERROR, "remote: %s", status + 4);
            } else {
                strcpy(ERROR, "remote failure");
            }
            return -1;
        }

        if (!memcmp(status, "DATA", 4) && size > 0){
            uint32_t dsize = strtol(status + 4, 0, 16);
            if (dsize > size) {
                strcpy(ERROR, "data size too large");
                transport->Close();
                return -1;
            }
            return dsize;
        }

        strcpy(ERROR,"unknown status code");
        transport->Close();
        break;
    }

    return -1;
}

static int _command_start(Transport* transport, const char* cmd, uint32_t size, char* response) {
    size_t cmdsize = strlen(cmd);
    if (cmdsize > 64) {
        sprintf(ERROR, "command too large");
        return -1;
    }

    if (response) {
        response[0] = 0;
    }

    if (transport->Write(cmd, cmdsize) != static_cast<int>(cmdsize)) {
        sprintf(ERROR, "command write failed (%s)", strerror(errno));
        transport->Close();
        return -1;
    }

    return check_response(transport, size, response);
}

static int _command_data(Transport* transport, const void* data, uint32_t size) {
    int r = transport->Write(data, size);
    if (r < 0) {
        sprintf(ERROR, "data transfer failure (%s)", strerror(errno));
        transport->Close();
        return -1;
    }
    if (r != ((int) size)) {
        sprintf(ERROR, "data transfer failure (short transfer)");
        transport->Close();
        return -1;
    }
    return r;
}

static int _command_end(Transport* transport) {
    return check_response(transport, 0, 0) < 0 ? -1 : 0;
}

static int _command_send(Transport* transport, const char* cmd, const void* data, uint32_t size,
                         char* response) {
    if (size == 0) {
        return -1;
    }

    int r = _command_start(transport, cmd, size, response);
    if (r < 0) {
        return -1;
    }

    r = _command_data(transport, data, size);
    if (r < 0) {
        return -1;
    }

    r = _command_end(transport);
    if (r < 0) {
        return -1;
    }

    return size;
}

static int _command_send_no_data(Transport* transport, const char* cmd, char* response) {
    return _command_start(transport, cmd, 0, response);
}

int fb_command(Transport* transport, const char* cmd) {
    return _command_send_no_data(transport, cmd, 0);
}

int fb_command_response(Transport* transport, const char* cmd, char* response) {
    return _command_send_no_data(transport, cmd, response);
}

int fb_download_data(Transport* transport, const void* data, uint32_t size) {
    char cmd[64];
    sprintf(cmd, "download:%08x", size);
    return _command_send(transport, cmd, data, size, 0) < 0 ? -1 : 0;
}

#define TRANSPORT_BUF_SIZE 1024
static char transport_buf[TRANSPORT_BUF_SIZE];
static int64_t transport_buf_len;

static int fb_download_data_sparse_write(void *priv, const void *data, int64_t len)
{
    int r;
    Transport* transport = reinterpret_cast<Transport*>(priv);
    int to_write;
    const char* ptr = reinterpret_cast<const char*>(data);

    if (transport_buf_len) {
        to_write = std::min(TRANSPORT_BUF_SIZE - transport_buf_len, len);

        memcpy(transport_buf + transport_buf_len, ptr, to_write);
        transport_buf_len += to_write;
        ptr += to_write;
        len -= to_write;
    }

    if (transport_buf_len == TRANSPORT_BUF_SIZE) {
        r = _command_data(transport, transport_buf, TRANSPORT_BUF_SIZE);
        if (r != TRANSPORT_BUF_SIZE) {
            return -1;
        }
        transport_buf_len = 0;
    }

    if (len > TRANSPORT_BUF_SIZE) {
        if (transport_buf_len > 0) {
            sprintf(ERROR, "internal error: transport_buf not empty\n");
            return -1;
        }
        to_write = round_down(len, TRANSPORT_BUF_SIZE);
        r = _command_data(transport, ptr, to_write);
        if (r != to_write) {
            return -1;
        }
        ptr += to_write;
        len -= to_write;
    }

    if (len > 0) {
        if (len > TRANSPORT_BUF_SIZE) {
            sprintf(ERROR, "internal error: too much left for transport_buf\n");
            return -1;
        }
        memcpy(transport_buf, ptr, len);
        transport_buf_len = len;
    }

    return 0;
}

static int fb_download_data_sparse_flush(Transport* transport) {
    if (transport_buf_len > 0) {
        if (_command_data(transport, transport_buf, transport_buf_len) != transport_buf_len) {
            return -1;
        }
        transport_buf_len = 0;
    }
    return 0;
}

int fb_download_data_sparse(Transport* transport, struct sparse_file* s) {
    int size = sparse_file_len(s, true, false);
    if (size <= 0) {
        return -1;
    }

    char cmd[64];
    sprintf(cmd, "download:%08x", size);
    int r = _command_start(transport, cmd, size, 0);
    if (r < 0) {
        return -1;
    }

    r = sparse_file_callback(s, true, false, fb_download_data_sparse_write, transport);
    if (r < 0) {
        return -1;
    }

    r = fb_download_data_sparse_flush(transport);
    if (r < 0) {
        return -1;
    }

    return _command_end(transport);
}

static int dump_file(Transport *transport, const char *file_name)
{
    static unsigned long long size, read_size, left_size;
    int r, ret = 0;
    char *buff = (char *)malloc(BULK_SIZE);
    FILE *file = NULL;

    if (!buff)
        die("out of memory");
    memset(buff, 0, BULK_SIZE);

    file = fopen(file_name, "wb");
    if (file == NULL) {
        die("open file failed");
    }

    /* get data size: DATA%016llx */
    r = transport->Read(buff, 20);
    if(r < 0) {
        sprintf(ERROR, "status read failed (%s)", strerror(errno));
        transport->Close();
        ret = -1;
        goto out;
    }

    if (sscanf(buff, "DATA%016llx", &size) == EOF) {
        sprintf(ERROR, "invalid protocol(%s)", buff);
        transport->Close();
        ret = -1;
        goto out;
    }

    left_size = size; read_size = 0;

    /* start to read the data */
    while (left_size > 0) {
        r = left_size > BULK_SIZE ? BULK_SIZE : left_size;
        r = transport->Read(buff, r);
        if (r < 0) {
            sprintf(ERROR, "status read failed (%s)", strerror(errno));
            transport->Close();
            ret = -1;
            goto out;
        }
        /* write data into file */
        if (fwrite(buff, 1, r, file) < (size_t)r) {
            sprintf(ERROR, "status write failed (%s)", strerror(errno));
            transport->Close();
            ret = -1;
            goto out;
        }
        left_size -= r;
        read_size += r;
        fprintf(stderr, "\b\b\b\b\b\b\b");
        fprintf(stderr, "%.2f%%", (100.0 * read_size / size));
    }

    fprintf(stderr, "\b\b\b\b\b\b\b");
out:
    if (file != NULL) fclose(file);
    if (buff) free(buff);
    return ret;
}

int fb_dump_data(Transport *transport, const char *file_name)
{
    if (dump_file(transport, file_name) < 0) {
        return -1;
    }

    if (check_response(transport, 0, 0) < 0)
        return -1;

    return 0;
}

static int dir_exist(const char *dir_name)
{
    struct stat st;

    if (stat(dir_name, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 1;
        } else
            return -1;
     } else {
            return 0;
     }
}

#define RAM_DUMP_DIR    "ramdump"
#ifdef _WIN32
#define FILE_SPLIT      "\\"
#else
#define FILE_SPLIT      "/"
#endif

static int create_ramdump_dir(void)
{
    int ret;

    /* search and rename old ramdump file */
    if ((ret = dir_exist(RAM_DUMP_DIR)) == 1) {
        /* rename the directory */
        int i = 0;
        while (1) {
            char new_name[16] = {0};

            sprintf(new_name, "%s_%d", RAM_DUMP_DIR, i++);
            if (dir_exist(new_name) == 0) {
                if (rename(RAM_DUMP_DIR, new_name) == 0)
                    break;
                else {
                    sprintf(ERROR, "failed to rename %s to %s: %s",
                        RAM_DUMP_DIR, new_name, strerror(errno));
                    return -1;
                }
            }
        }
    } else if (ret == -1) {
        sprintf(ERROR, "non-directory %s exists, please rename it", RAM_DUMP_DIR);
        return -1;
    }

    /* create dir */
#ifdef _WIN32
    if (mkdir(RAM_DUMP_DIR) == -1) {
#else
    if (mkdir(RAM_DUMP_DIR, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == -1) {
#endif
        sprintf(ERROR, "failed to create directory %s: %s", RAM_DUMP_DIR, strerror(errno));
        return -1;
    }

    return 0;
}

/*
 * function fb_ramdump_files is used to dump the file[s] from phone side.
 * fastboot will dump the ram files one by one according to the received
 * file list in fb_query_ramdump_files.
 */
int fb_dump_ram_files(Transport *transport)
{
    int ret = 0;
    char cmd_buffer[64] = {0};

    /* create the ramdump folder */
    ret= create_ramdump_dir();
    if (ret < 0) {
        transport->Close();
        return -1;
    }

    while (true) {
        int file_name_len;
        char ram_file[24] = {0};
        char file_name[32] = {0};

        /* get ram file name: DUMP%04xfile */
        ret = transport->Read(cmd_buffer, 64);
        if(ret < 0) {
             sprintf(ERROR, "status read failed (%s)", strerror(errno));
             transport->Close();
             return -1;
        }
        if (ret < 8) {
            sprintf(ERROR, "invalid dump command (%s)", cmd_buffer);
            transport->Close();
            return -1;
        }

        if (strcmp(cmd_buffer, "DUMPDONE") == 0) {
            return check_response(transport, 0, 0);
        }

        if (sscanf(cmd_buffer, "DUMP%04x", &file_name_len) == EOF) {
            sprintf(ERROR, "invalid protocol(%s)", cmd_buffer);
            transport->Close();
            return -1;
        }

        memcpy(ram_file, cmd_buffer + 8, file_name_len);
        snprintf(file_name, 32, "%s%s%s", RAM_DUMP_DIR, FILE_SPLIT, ram_file);

        /* response "OKAY" to sync the protocol */
        memset(cmd_buffer, 0, 64);
        sprintf(cmd_buffer, "OKAY");
        if (transport->Write("OKAY", 4) < 0) {
            transport->Close();
            return -1;
        }

        fprintf(stderr, "Receiving \"%s\"...\n", ram_file);

        /* start to recive file */
        if (dump_file(transport, file_name) == -1) {
            sprintf(cmd_buffer, "failed to dump ram file %s", ram_file);
            return -1;
        }
    }

    return 0;
}
