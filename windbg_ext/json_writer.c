#include "json_writer.h"

#include <stdio.h>

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
