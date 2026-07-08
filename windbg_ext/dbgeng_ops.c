#include "dbgeng_ops.h"

#include <stdio.h>
#include <string.h>

static char g_dbgeng_last_error[256] = "ok";

static void DvsSetDbgEngLastError(const char *message, HRESULT hr)
{
    snprintf(g_dbgeng_last_error, sizeof(g_dbgeng_last_error), "%s hr=0x%08lx", message, (unsigned long)hr);
    g_dbgeng_last_error[sizeof(g_dbgeng_last_error) - 1] = '\0';
}

static void DvsSetDbgEngLastErrorText(const char *message)
{
    strncpy(g_dbgeng_last_error, message, sizeof(g_dbgeng_last_error) - 1);
    g_dbgeng_last_error[sizeof(g_dbgeng_last_error) - 1] = '\0';
}

const char *DvsDbgEngLastError(void)
{
    return g_dbgeng_last_error;
}

static void DvsCopyModuleName(char *dst, unsigned long dst_size, const char *src)
{
    if (dst_size == 0) {
        return;
    }
    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

int DvsReadCurrentPcInfo(PDEBUG_CLIENT client, DVS_PC_INFO *info)
{
    HRESULT hr;
    PDEBUG_REGISTERS registers = NULL;
    PDEBUG_SYMBOLS symbols = NULL;
    ULONG module_index = 0;
    ULONG64 module_base = 0;
    ULONG image_name_size = 0;
    ULONG module_name_size = 0;
    char image_name[DVS_MODULE_NAME_MAX];
    char module_name[DVS_MODULE_NAME_MAX];

    if (client == NULL || info == NULL) {
        DvsSetDbgEngLastErrorText("client or output info is null");
        return DVS_DBGENG_ERROR;
    }

    memset(info, 0, sizeof(*info));
    memset(image_name, 0, sizeof(image_name));
    memset(module_name, 0, sizeof(module_name));

    hr = client->lpVtbl->QueryInterface(
        client,
        &IID_IDebugRegisters,
        (void **)&registers);
    if (FAILED(hr) || registers == NULL) {
        DvsSetDbgEngLastError("QueryInterface(IDebugRegisters) failed", hr);
        return DVS_DBGENG_ERROR;
    }

    hr = registers->lpVtbl->GetInstructionOffset(registers, &info->pc);
    registers->lpVtbl->Release(registers);
    registers = NULL;
    if (FAILED(hr)) {
        DvsSetDbgEngLastError("IDebugRegisters::GetInstructionOffset failed", hr);
        return DVS_DBGENG_ERROR;
    }

    hr = client->lpVtbl->QueryInterface(
        client,
        &IID_IDebugSymbols,
        (void **)&symbols);
    if (FAILED(hr) || symbols == NULL) {
        DvsSetDbgEngLastError("QueryInterface(IDebugSymbols) failed", hr);
        return DVS_DBGENG_ERROR;
    }

    hr = symbols->lpVtbl->GetModuleByOffset(symbols, info->pc, 0, &module_index, &module_base);
    if (FAILED(hr)) {
        symbols->lpVtbl->Release(symbols);
        DvsSetDbgEngLastError("IDebugSymbols::GetModuleByOffset failed", hr);
        return DVS_DBGENG_ERROR;
    }

    hr = symbols->lpVtbl->GetModuleNames(
        symbols,
        module_index,
        module_base,
        image_name,
        sizeof(image_name),
        &image_name_size,
        module_name,
        sizeof(module_name),
        &module_name_size,
        NULL,
        0,
        NULL);
    symbols->lpVtbl->Release(symbols);
    symbols = NULL;
    if (FAILED(hr)) {
        DvsSetDbgEngLastError("IDebugSymbols::GetModuleNames failed", hr);
        return DVS_DBGENG_ERROR;
    }

    info->runtime_module_base = module_base;
    if (module_name[0] != '\0') {
        DvsCopyModuleName(info->module, sizeof(info->module), module_name);
    } else if (image_name[0] != '\0') {
        DvsCopyModuleName(info->module, sizeof(info->module), image_name);
    } else {
        DvsSetDbgEngLastErrorText("module name is empty");
        return DVS_DBGENG_ERROR;
    }

    DvsSetDbgEngLastErrorText("ok");
    return DVS_DBGENG_OK;
}
