/* system/debuggerd/utility.h
**
** Copyright 2008, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License"); 
** you may not use this file except in compliance with the License. 
** You may obtain a copy of the License at 
**
**     http://www.apache.org/licenses/LICENSE-2.0 
**
** Unless required by applicable law or agreed to in writing, software 
** distributed under the License is distributed on an "AS IS" BASIS, 
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
** See the License for the specific language governing permissions and 
** limitations under the License.
*/

#ifndef __utility_h
#define __utility_h

#include <stddef.h>
#include <stdbool.h>

#include "symbol_table.h"

#ifndef PT_ARM_EXIDX
#define PT_ARM_EXIDX    0x70000001      /* .ARM.exidx segment */
#endif

#define STACK_CONTENT_DEPTH 32

typedef struct mapinfo {
    struct mapinfo *next;
    unsigned start;
    unsigned end;
    unsigned exidx_start;
    unsigned exidx_end;
    struct symbol_table *symbols;
    bool isExecutable;
    char name[];
} mapinfo;

/* Get a word from pid using ptrace. The result is the return value. */
extern int get_remote_word(int pid, void *src);

/* Handy routine to read aggregated data from pid using ptrace. The read 
 * values are written to the dest locations directly. 
 */
extern void get_remote_struct(int pid, void *src, void *dst, size_t size);

/* Find the containing map for the pc */
const mapinfo *pc_to_mapinfo (mapinfo *mi, unsigned pc, unsigned *rel_pc);

/* Map a pc address to the name of the containing ELF file */
const char *map_to_name(mapinfo *mi, unsigned pc, const char* def);

/* Log information onto the tombstone */
extern void _LOG(int tfd, bool in_tombstone_only, const char *fmt, ...);

/* Determine whether si_addr is valid for this signal */
bool signal_has_address(int sig);

#define LOG(fmt...) _LOG(-1, 0, fmt)

/* Set to 1 for normal debug traces */
#if 0
#define XLOG(fmt...) _LOG(-1, 0, fmt)
#else
#define XLOG(fmt...) do {} while(0)
#endif

/* Set to 1 for chatty debug traces. Includes all resolved dynamic symbols */
#if 0
#define XLOG2(fmt...) _LOG(-1, 0, fmt)
#else
#define XLOG2(fmt...) do {} while(0)
#endif

#endif
