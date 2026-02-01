#ifndef idevicebackup2_h
#define idevicebackup2_h

#include <stdio.h>

extern int restore_debug_mode;
extern int show_file_digests;
extern int abort_on_missing_files;
int mainLOL(char *path, char *uuidi, char *backup_password, int restore_system_files);

#endif /* idevicebackup2_h */
