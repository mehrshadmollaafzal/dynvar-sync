#include "dbgeng_ops.h"

#include <string.h>

int DvsReadCurrentPcInfo(DVS_PC_INFO *info)
{
    if (info == 0) {
        return DVS_DBGENG_PLACEHOLDER;
    }

    info->pc = 0xfffff8010dac9cb0ULL;
    info->runtime_module_base = 0xfffff8010d400000ULL;
    strncpy(info->module, "phase2-placeholder-module", sizeof(info->module) - 1);
    info->module[sizeof(info->module) - 1] = '\0';
    info->is_placeholder = 1;
    return DVS_DBGENG_PLACEHOLDER;
}
