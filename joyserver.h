#ifndef __JOY_SERVER_H
#define __JOY_SERVER_H

#include <sys/epoll.h>
#include "joynet.h"

#define kJoyServerEpollTimeOut 5
#define kJoyServerSendBufSize 1 * 1024 * 1024   //1MB发送缓存
#define kJoyServerRecvBufSize 1 * 1024 * 1024   //1MB接受缓存
#define kListenBacklog  1024                    //建立连接(ESTABLISHED状态)的最大数量


#ifdef __cplusplus
extern "C" {
#endif

struct JoyServer {
    int efd;                                //epoll fd
    int lfd;                                //监听fd
    struct JoyConnectPool cpool;            //连接池
};

int joyServerListen(const char *addr, int port);
int joyServerCloseTcp();
int joyServerProcRecvData();
int joyServerRecvData(joyRecvCallBack recvCallBack);
int joyServerProcSendData();
int joyServerSendData(const char *buf, int len, int procid, int srcid, int dstid);

#ifdef __cplusplus
}
#endif

#endif
