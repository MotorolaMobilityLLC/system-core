#ifndef _FS_H_
#define _FH_H_

#include <stdint.h>

struct fs_generator;

const struct fs_generator* fs_get_generator(const char* name);
int fs_generator_generate(const struct fs_generator* gen, int tmpFileNo, long long partSize);

#endif

