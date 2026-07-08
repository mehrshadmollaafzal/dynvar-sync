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

static int DvsAppendJsonEscapedString(
    char *buffer,
    unsigned long buffer_size,
    unsigned long *offset,
    const char *value)
{
    const unsigned char *p = (const unsigned char *)value;

    if (DvsAppendJson(buffer, buffer_size, offset, "\"") != DVS_JSON_OK) {
        return DVS_JSON_ERROR;
    }

    while (*p != '\0') {
        switch (*p) {
        case '"':
            if (DvsAppendJson(buffer, buffer_size, offset, "\\\"") != DVS_JSON_OK) {
                return DVS_JSON_ERROR;
            }
            break;
        case '\\':
            if (DvsAppendJson(buffer, buffer_size, offset, "\\\\") != DVS_JSON_OK) {
                return DVS_JSON_ERROR;
            }
            break;
        case '\b':
            if (DvsAppendJson(buffer, buffer_size, offset, "\\b") != DVS_JSON_OK) {
                return DVS_JSON_ERROR;
            }
            break;
        case '\f':
            if (DvsAppendJson(buffer, buffer_size, offset, "\\f") != DVS_JSON_OK) {
                return DVS_JSON_ERROR;
            }
            break;
        case '\n':
            if (DvsAppendJson(buffer, buffer_size, offset, "\\n") != DVS_JSON_OK) {
                return DVS_JSON_ERROR;
            }
            break;
        case '\r':
            if (DvsAppendJson(buffer, buffer_size, offset, "\\r") != DVS_JSON_OK) {
                return DVS_JSON_ERROR;
            }
            break;
        case '\t':
            if (DvsAppendJson(buffer, buffer_size, offset, "\\t") != DVS_JSON_OK) {
                return DVS_JSON_ERROR;
            }
            break;
        default:
            if (*p < 0x20) {
                if (DvsAppendJson(buffer, buffer_size, offset, "\\u%04x", (unsigned int)*p) != DVS_JSON_OK) {
                    return DVS_JSON_ERROR;
                }
            } else {
                if (DvsAppendJson(buffer, buffer_size, offset, "%c", *p) != DVS_JSON_OK) {
                    return DVS_JSON_ERROR;
                }
            }
            break;
        }
        p++;
    }

    return DvsAppendJson(buffer, buffer_size, offset, "\"");
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
            "\"payload\":{\"pc_seq\":%lu,\"request_id\":",
            message_id,
            pc_seq) != DVS_JSON_OK ||
        DvsAppendJsonEscapedString(buffer, buffer_size, &offset, request_id) != DVS_JSON_OK ||
        DvsAppendJson(buffer, buffer_size, &offset, ",\"runtime_pc\":") != DVS_JSON_OK ||
        DvsAppendJsonEscapedString(buffer, buffer_size, &offset, runtime_pc) != DVS_JSON_OK ||
        DvsAppendJson(buffer, buffer_size, &offset, ",\"ok\":true,\"registers\":{") != DVS_JSON_OK) {
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

int DvsWriteMemResponse(
    char *buffer,
    unsigned long buffer_size,
    unsigned long message_id,
    unsigned long pc_seq,
    const char *request_id,
    const char *runtime_pc,
    const char *address,
    unsigned long size,
    const unsigned char *bytes,
    unsigned long bytes_len)
{
    static const char hex_digits[] = "0123456789abcdef";
    unsigned long offset = 0;
    unsigned long i;

    if (DvsAppendJson(
            buffer,
            buffer_size,
            &offset,
            "{\"protocol\":1,\"id\":%lu,\"type\":\"mem_response\",\"role\":\"windbg\","
            "\"payload\":{\"pc_seq\":%lu,\"request_id\":",
            message_id,
            pc_seq) != DVS_JSON_OK ||
        DvsAppendJsonEscapedString(buffer, buffer_size, &offset, request_id) != DVS_JSON_OK ||
        DvsAppendJson(buffer, buffer_size, &offset, ",\"runtime_pc\":") != DVS_JSON_OK ||
        DvsAppendJsonEscapedString(buffer, buffer_size, &offset, runtime_pc) != DVS_JSON_OK ||
        DvsAppendJson(buffer, buffer_size, &offset, ",\"ok\":true,\"address\":") != DVS_JSON_OK ||
        DvsAppendJsonEscapedString(buffer, buffer_size, &offset, address) != DVS_JSON_OK ||
        DvsAppendJson(buffer, buffer_size, &offset, ",\"size\":%lu,\"bytes_hex\":\"", size) != DVS_JSON_OK) {
        return DVS_JSON_ERROR;
    }

    for (i = 0; i < bytes_len; i++) {
        if (DvsAppendJson(
                buffer,
                buffer_size,
                &offset,
                "%c%c",
                hex_digits[(bytes[i] >> 4) & 0x0f],
                hex_digits[bytes[i] & 0x0f]) != DVS_JSON_OK) {
            return DVS_JSON_ERROR;
        }
    }

    return DvsAppendJson(buffer, buffer_size, &offset, "\"}}\n");
}

int DvsWriteMemErrorResponse(
    char *buffer,
    unsigned long buffer_size,
    unsigned long message_id,
    unsigned long pc_seq,
    const char *request_id,
    const char *runtime_pc,
    const char *address,
    unsigned long size,
    const char *code,
    const char *message)
{
    unsigned long offset = 0;

    if (DvsAppendJson(
            buffer,
            buffer_size,
            &offset,
            "{\"protocol\":1,\"id\":%lu,\"type\":\"mem_response\",\"role\":\"windbg\","
            "\"payload\":{\"pc_seq\":%lu,\"request_id\":",
            message_id,
            pc_seq) != DVS_JSON_OK ||
        DvsAppendJsonEscapedString(buffer, buffer_size, &offset, request_id) != DVS_JSON_OK ||
        DvsAppendJson(buffer, buffer_size, &offset, ",\"runtime_pc\":") != DVS_JSON_OK ||
        DvsAppendJsonEscapedString(buffer, buffer_size, &offset, runtime_pc) != DVS_JSON_OK ||
        DvsAppendJson(buffer, buffer_size, &offset, ",\"ok\":false,\"address\":") != DVS_JSON_OK ||
        DvsAppendJsonEscapedString(buffer, buffer_size, &offset, address) != DVS_JSON_OK ||
        DvsAppendJson(buffer, buffer_size, &offset, ",\"size\":%lu,\"error\":{\"code\":", size) != DVS_JSON_OK ||
        DvsAppendJsonEscapedString(buffer, buffer_size, &offset, code) != DVS_JSON_OK ||
        DvsAppendJson(buffer, buffer_size, &offset, ",\"message\":") != DVS_JSON_OK ||
        DvsAppendJsonEscapedString(buffer, buffer_size, &offset, message) != DVS_JSON_OK ||
        DvsAppendJson(buffer, buffer_size, &offset, "}}}\n") != DVS_JSON_OK) {
        return DVS_JSON_ERROR;
    }

    return DVS_JSON_OK;
}
