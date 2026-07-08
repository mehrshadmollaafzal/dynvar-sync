#ifndef DAYVAR_JSON_WRITER_H
#define DAYVAR_JSON_WRITER_H

#include "dbgeng_ops.h"

#define DVS_JSON_OK 0
#define DVS_JSON_ERROR (-1)

int DvsWriteHello(char *buffer, unsigned long buffer_size, unsigned long message_id);
int DvsWritePcUpdate(
    char *buffer,
    unsigned long buffer_size,
    unsigned long message_id,
    unsigned long pc_seq,
    unsigned long long pc,
    const char *module,
    unsigned long long runtime_module_base,
    const char *reason,
    int auto_live);
int DvsWriteRegResponse(
    char *buffer,
    unsigned long buffer_size,
    unsigned long message_id,
    unsigned long pc_seq,
    const char *request_id,
    const char *runtime_pc,
    const DVS_REGISTER_VALUE *values,
    unsigned long value_count);
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
    unsigned long bytes_len);
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
    const char *message);

#endif
