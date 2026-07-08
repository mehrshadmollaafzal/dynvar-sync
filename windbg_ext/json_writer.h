#ifndef DAYVAR_JSON_WRITER_H
#define DAYVAR_JSON_WRITER_H

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

#endif
