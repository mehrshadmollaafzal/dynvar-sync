#include "dbgeng_ops.h"

#include <ctype.h>
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

static int DvsAsciiEqualNoCase(const char *left, const char *right)
{
    while (*left != '\0' && *right != '\0') {
        if (tolower((unsigned char)*left) != tolower((unsigned char)*right)) {
            return 0;
        }
        left++;
        right++;
    }
    return *left == '\0' && *right == '\0';
}

static int DvsIsSupportedRegisterName(const char *name)
{
    static const char *supported[] = {
        "rax", "rbx", "rcx", "rdx",
        "rsi", "rdi", "rsp", "rbp",
        "r8", "r9", "r10", "r11",
        "r12", "r13", "r14", "r15",
        "rip"
    };
    unsigned long i;

    for (i = 0; i < sizeof(supported) / sizeof(supported[0]); i++) {
        if (DvsAsciiEqualNoCase(name, supported[i])) {
            return 1;
        }
    }
    return 0;
}

static unsigned long long DvsDebugValueToU64(const DEBUG_VALUE *value)
{
    switch (value->Type) {
    case DEBUG_VALUE_INT8:
        return (unsigned long long)value->I8;
    case DEBUG_VALUE_INT16:
        return (unsigned long long)value->I16;
    case DEBUG_VALUE_INT32:
        return (unsigned long long)value->I32;
    case DEBUG_VALUE_INT64:
        return (unsigned long long)value->I64;
    default:
        return 0;
    }
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

int DvsReadRegisters(
    PDEBUG_CLIENT client,
    const char names[][DVS_REGISTER_NAME_MAX],
    unsigned long count,
    DVS_REGISTER_VALUE *values,
    unsigned long *value_count)
{
    HRESULT hr;
    PDEBUG_REGISTERS registers = NULL;
    unsigned long i;
    unsigned long out_count = 0;

    if (client == NULL || names == NULL || values == NULL || value_count == NULL) {
        DvsSetDbgEngLastErrorText("invalid register read arguments");
        return DVS_DBGENG_ERROR;
    }

    *value_count = 0;

    hr = client->lpVtbl->QueryInterface(
        client,
        &IID_IDebugRegisters,
        (void **)&registers);
    if (FAILED(hr) || registers == NULL) {
        DvsSetDbgEngLastError("QueryInterface(IDebugRegisters) failed", hr);
        return DVS_DBGENG_ERROR;
    }

    for (i = 0; i < count && out_count < DVS_MAX_REGISTER_VALUES; i++) {
        ULONG reg_index = 0;
        DEBUG_VALUE value;

        memset(&value, 0, sizeof(value));
        memset(&values[out_count], 0, sizeof(values[out_count]));
        strncpy(values[out_count].name, names[i], sizeof(values[out_count].name) - 1);
        values[out_count].name[sizeof(values[out_count].name) - 1] = '\0';

        if (!DvsIsSupportedRegisterName(names[i])) {
            values[out_count].ok = 0;
            out_count++;
            continue;
        }

        hr = registers->lpVtbl->GetIndexByName(registers, names[i], &reg_index);
        if (FAILED(hr)) {
            values[out_count].ok = 0;
            out_count++;
            continue;
        }

        hr = registers->lpVtbl->GetValue(registers, reg_index, &value);
        if (FAILED(hr)) {
            values[out_count].ok = 0;
            out_count++;
            continue;
        }

        values[out_count].value = DvsDebugValueToU64(&value);
        values[out_count].ok = 1;
        out_count++;
    }

    registers->lpVtbl->Release(registers);
    *value_count = out_count;
    DvsSetDbgEngLastErrorText("ok");
    return DVS_DBGENG_OK;
}

int DvsReadVirtualMemory(
    PDEBUG_CLIENT client,
    unsigned long long address,
    unsigned long size,
    unsigned char *bytes,
    unsigned long *bytes_read)
{
    HRESULT hr;
    PDEBUG_DATA_SPACES data_spaces = NULL;
    ULONG actual = 0;

    if (client == NULL || bytes == NULL || bytes_read == NULL) {
        DvsSetDbgEngLastErrorText("invalid memory read arguments");
        return DVS_DBGENG_ERROR;
    }

    *bytes_read = 0;

    if (size == 0 || size > DVS_MAX_MEMORY_READ_SIZE) {
        DvsSetDbgEngLastErrorText("invalid memory read size");
        return DVS_DBGENG_ERROR;
    }

    hr = client->lpVtbl->QueryInterface(
        client,
        &IID_IDebugDataSpaces,
        (void **)&data_spaces);
    if (FAILED(hr) || data_spaces == NULL) {
        DvsSetDbgEngLastError("QueryInterface(IDebugDataSpaces) failed", hr);
        return DVS_DBGENG_ERROR;
    }

    hr = data_spaces->lpVtbl->ReadVirtual(data_spaces, address, bytes, size, &actual);
    data_spaces->lpVtbl->Release(data_spaces);
    if (FAILED(hr)) {
        DvsSetDbgEngLastError("IDebugDataSpaces::ReadVirtual failed", hr);
        return DVS_DBGENG_ERROR;
    }

    if (actual != size) {
        DvsSetDbgEngLastErrorText("partial memory read");
        *bytes_read = actual;
        return DVS_DBGENG_ERROR;
    }

    *bytes_read = actual;
    DvsSetDbgEngLastErrorText("ok");
    return DVS_DBGENG_OK;
}
