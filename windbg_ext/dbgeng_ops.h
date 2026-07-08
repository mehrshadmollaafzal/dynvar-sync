#ifndef DAYVAR_DBGENG_OPS_H
#define DAYVAR_DBGENG_OPS_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbgeng.h>

#define DVS_DBGENG_OK 0
#define DVS_DBGENG_ERROR (-1)
#define DVS_MODULE_NAME_MAX 128
#define DVS_REGISTER_NAME_MAX 16
#define DVS_MAX_REGISTER_VALUES 32
#define DVS_MAX_MEMORY_READ_SIZE 4096

typedef struct DVS_PC_INFO {
    unsigned long long pc;
    unsigned long long runtime_module_base;
    char module[DVS_MODULE_NAME_MAX];
} DVS_PC_INFO;

typedef struct DVS_REGISTER_VALUE {
    char name[DVS_REGISTER_NAME_MAX];
    unsigned long long value;
    int ok;
} DVS_REGISTER_VALUE;

int DvsReadCurrentPcInfo(PDEBUG_CLIENT client, DVS_PC_INFO *info);
int DvsReadRegisters(
    PDEBUG_CLIENT client,
    const char names[][DVS_REGISTER_NAME_MAX],
    unsigned long count,
    DVS_REGISTER_VALUE *values,
    unsigned long *value_count);
int DvsReadVirtualMemory(
    PDEBUG_CLIENT client,
    unsigned long long address,
    unsigned long size,
    unsigned char *bytes,
    unsigned long *bytes_read);
const char *DvsDbgEngLastError(void);

#endif
