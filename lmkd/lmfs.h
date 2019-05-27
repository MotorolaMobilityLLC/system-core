#ifndef __LMFS_H__
#define __LMFS_H__


void start_lmfs(void) ;
void notify_lmfs_process_killed(int pid);
void handle_vmpressure(int vmpressure);
#endif