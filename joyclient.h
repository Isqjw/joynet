#ifndef __JOY_CLIENT_H
#define __JOY_CLIENT_H

#include <poll.h>
#include "joynet.h"

#define kJoyClientPollTimeOut 0
#define kJoyClientConnectTimeOut 10
#define kJoyClientSendBufSize 10 * 1024 * 1024   //10MB发送缓存
#define kJoyClientRecvBufSize 10 * 1024 * 1024   //10MB接受缓存

#ifdef __cplusplus
extern "C" {
#endif

struct JoyClient {
    struct JoyConnectPool cpool;            //连接池
};

int joyClientConnectTcp(const char *addr, int port, int procid);
int joyClientCloseTcp(int fd);
int joyClientProcRecvData();
int joyServerRecvData(joyRecvCallBack recvCallBack);
int joyClientProcSendData();
int joyClientSendData(const char *buf, int len, int srcid, int dstid);

#ifdef __cplusplus
}
#endif

#endif
