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
int joyClientIsReady(int procid);
int joyClientCloseTcp(int procid);
int joyClientProcRecvData();
int joyClientRecvData(joyRecvCallBack recvCallBack);
int joyClientProcSendData();
int joyClientSendData(const char *buf, int len, int procid, int srcid, int dstid);

// 为了兼容发送时只知道nid不知道procid的情况
int joyClientSendDataByNid(const char *buf, int len, int procid, int srcid, int dstnid);
int joyClientRegisterNid(int procid, int srcid, int nid);

#ifdef __cplusplus
}
#endif

#endif
