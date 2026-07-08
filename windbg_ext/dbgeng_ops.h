#ifndef DAYVAR_DBGENG_OPS_H
#define DAYVAR_DBGENG_OPS_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbgeng.h>

#define DVS_DBGENG_OK 0
#define DVS_DBGENG_ERROR (-1)
#define DVS_MODULE_NAME_MAX 128

typedef struct DVS_PC_INFO {
    unsigned long long pc;
    unsigned long long runtime_module_base;
    char module[DVS_MODULE_NAME_MAX];
} DVS_PC_INFO;

int DvsReadCurrentPcInfo(PDEBUG_CLIENT client, DVS_PC_INFO *info);
const char *DvsDbgEngLastError(void);

#endif
