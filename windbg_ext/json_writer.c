#include "json_writer.h"

#include <stdio.h>
#include <stdarg.h>

static int DvsCheckWriteResult(int written, unsigned long buffer_size)
{
    if (written < 0 || (unsigned long)written >= buffer_size) {
        return DVS_JSON_ERROR;
    }
    return DVS_JSON_OK;
}

int DvsWriteHello(char *buffer, unsigned long buffer_size, unsigned long message_id)
{
    int written = snprintf(
        buffer,
        buffer_size,
        "{\"protocol\":1,\"id\":%lu,\"type\":\"hello\",\"role\":\"windbg\","
        "\"payload\":{\"client_name\":\"dayvar-windbg-ext\",\"version\":\"0.1\"}}\n",
        message_id);
    return DvsCheckWriteResult(written, buffer_size);
}

int DvsWritePcUpdate(
    char *buffer,
    unsigned long buffer_size,
    unsigned long message_id,
    unsigned long pc_seq,
    unsigned long long pc,
    const char *module,
    unsigned long long runtime_module_base,
    const char *reason,
    int auto_live)
{
    int written = snprintf(
        buffer,
        buffer_size,
        "{\"protocol\":1,\"id\":%lu,\"type\":\"pc_update\",\"role\":\"windbg\","
        "\"payload\":{\"pc_seq\":%lu,\"pc\":\"0x%016llx\",\"module\":\"%s\","
        "\"runtime_module_base\":\"0x%016llx\",\"auto_live\":%s,\"reason\":\"%s\"}}\n",
        message_id,
        pc_seq,
        pc,
        module,
        runtime_module_base,
        auto_live ? "true" : "false",
        reason);
    return DvsCheckWriteResult(written, buffer_size);
}

static int DvsAppendJson(char *buffer, unsigned long buffer_size, unsigned long *offset, const char *format, ...)
{
    int written;
    va_list args;

    if (*offset >= buffer_size) {
        return DVS_JSON_ERROR;
    }

    va_start(args, format);
    written = vsnprintf(buffer + *offset, buffer_size - *offset, format, args);
    va_end(args);

    if (written < 0 || (unsigned long)written >= buffer_size - *offset) {
        return DVS_JSON_ERROR;
    }

    *offset += (unsigned long)written;
    return DVS_JSON_OK;
}

int DvsWriteRegResponse(
    char *buffer,
    unsigned long buffer_size,
    unsigned long message_id,
    unsigned long pc_seq,
    const char *request_id,
    const char *runtime_pc,
    const DVS_REGISTER_VALUE *values,
    unsigned long value_count)
{
    unsigned long offset = 0;
    unsigned long i;
    int first = 1;

    if (DvsAppendJson(
            buffer,
            buffer_size,
            &offset,
            "{\"protocol\":1,\"id\":%lu,\"type\":\"reg_response\",\"role\":\"windbg\","
            "\"payload\":{\"pc_seq\":%lu,\"request_id\":\"%s\",\"runtime_pc\":\"%s\","
            "\"ok\":true,\"registers\":{",
            message_id,
            pc_seq,
            request_id,
            runtime_pc) != DVS_JSON_OK) {
        return DVS_JSON_ERROR;
    }

    for (i = 0; i < value_count; i++) {
        if (!values[i].ok) {
            continue;
        }
        if (DvsAppendJson(
                buffer,
                buffer_size,
                &offset,
                "%s\"%s\":\"0x%016llx\"",
                first ? "" : ",",
                values[i].name,
                values[i].value) != DVS_JSON_OK) {
            return DVS_JSON_ERROR;
        }
        first = 0;
    }

    if (DvsAppendJson(buffer, buffer_size, &offset, "}}}\n") != DVS_JSON_OK) {
        return DVS_JSON_ERROR;
    }

    return DVS_JSON_OK;
}
