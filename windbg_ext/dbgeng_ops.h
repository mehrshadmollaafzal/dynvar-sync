#ifndef DAYVAR_DBGENG_OPS_H
#define DAYVAR_DBGENG_OPS_H

#define DVS_DBGENG_OK 0
#define DVS_DBGENG_PLACEHOLDER 1
#define DVS_MODULE_NAME_MAX 128

typedef struct DVS_PC_INFO {
    unsigned long long pc;
    unsigned long long runtime_module_base;
    char module[DVS_MODULE_NAME_MAX];
    int is_placeholder;
} DVS_PC_INFO;

int DvsReadCurrentPcInfo(DVS_PC_INFO *info);

#endif
