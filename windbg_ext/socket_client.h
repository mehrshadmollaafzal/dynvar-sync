#ifndef DAYVAR_SOCKET_CLIENT_H
#define DAYVAR_SOCKET_CLIENT_H

#define DVS_SOCKET_OK 0
#define DVS_SOCKET_ERROR (-1)

int DvsSocketConnect(const char *host, unsigned short port);
void DvsSocketDisconnect(void);
int DvsSocketIsConnected(void);
int DvsSocketSendAll(const char *data, unsigned long data_len);
const char *DvsSocketLastError(void);

#endif
