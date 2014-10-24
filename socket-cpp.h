#ifndef _SOCKET_H
#define _SOCKET_H

#define int32 int
#define uint32 unsigned int32

#include "byteorder.h"

typedef int SOCKET;
typedef enum {E_NET_ERRNO=-1, E_NET_OK=0} NetErrnoType;
typedef struct ClientStruct *ClientPtr;

struct ClientStruct
{
    int fd;
    char hostname[200];
};

extern "C" {
    const char *NetErrStr();
    NetErrnoType NetErrNo();

    SOCKET NetMakeWelcome(int port);
    int NetNewConnection(SOCKET w, ClientPtr newc);
    int NetClientDataAvail(ClientPtr c);
    char *NetGetClientHostname(ClientPtr c, char *hname, int maxhostlen);
    void NetCloseConnection(ClientPtr c);
    int NetGetAddr(char *hname);


    void InitClient(ClientPtr cl);
    void ResetClient(ClientPtr cl);
    void SetClientFd(ClientPtr cl, SOCKET fd);
    SOCKET GetClientFd(ClientPtr cl);
    void CloseClient(ClientPtr cl);
    char *GetClientHname(ClientPtr cl);
    int GetClientMaxHlen(ClientPtr cl);
    void HandleNetError();

    SOCKET NetMakeContact(const char *hostname, int port);
    extern void child_signal();


    extern int write_buf(int fd, char *buf, size_t len);
    extern int write_int(int f,int32 x);
    extern int read_buf(int fd, char *buf, size_t len);
    extern int read_int(int f, int32 *val);
};




#endif /* _SOCKET_H */
