#include <string.h>
#include <arpa/inet.h>
#include "joyclient.h"


static struct JoyClient joyClient;

static int joyClientCheckConnectByPoll_(int sockfd) {
    struct pollfd pfd[1];
    pfd[0].fd = sockfd;
    pfd[0].events = POLLOUT;
    int rv = poll(pfd, 1, kJoyClientPollTimeOut);
    if (rv < 0) {
        return -1;
    } else if (0 == rv) {
        //超时特殊处理
        return 1;
    }

    int err = 0;
    unsigned int len = sizeof(err);
    rv = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
    if (rv < 0 || 0 != err) {
        return -1;
    } else {
        return 0;
    }
}

static int joyClientCloseTcp_(int fd)
{
    close(fd);
    debug_msg("debug: close fd[%d].", fd);
    if (0 != joynetDelConnectNode(&joyClient.cpool, fd)) {
        debug_msg("error: fail to del node, fd[%d].", fd);
    }
    return 0;
}

static int joyClientSetConnected_(int fd)
{
    int nodepos = joynetGetConnectNodePosByFD(&joyClient.cpool, fd);
    if (nodepos < 0) {
        debug_msg("error: fail to get node by fd[%d].", fd);
        return -1;
    }
    struct JoyConnectNode *node = joyClient.cpool.node + nodepos;
    node->status = kJoynetStatusConnected;
    debug_msg("debug: set fd[%d] status to connected.", node->cfd);

    struct JoynetHead pkghead = { 0 };
    pkghead.headlen = sizeof(pkghead);
    pkghead.bodylen = 0;
    pkghead.srcid = node->procid;
    pkghead.dstid = 0;
    pkghead.md5 = 0;
    pkghead.msgtype = kJoynetMsgTypeShake;

    // 初始化一个握手包
    if (0 != joynetWriteSendBuf(node, (char *)(&pkghead), pkghead.headlen)) {
        debug_msg("error: fail to write send buf.");
        joyClientCloseTcp_(node->cfd);
        return -1;
    }
    return 0;
}

int joyClientCloseTcp(int procid)
{
    int nodepos = joynetGetConnectNodePosByID(&joyClient.cpool, procid);
    if (nodepos < 0) {
        debug_msg("fail to get node by id[%d].", procid);
        return -1;
    }
    struct JoyConnectNode *node = joyClient.cpool.node + nodepos;
    joyClientCloseTcp_(node->cfd);
    return 0;
}

int joyClientConnectTcp(const char *addr, int port, int procid)
{
    time_t tick;
    time(&tick);

    struct JoyConnectNode *node = NULL;
    int nodepos = joynetGetConnectNodePosByID(&joyClient.cpool, procid);
    if (0 <= nodepos) {
        node = joyClient.cpool.node + nodepos;
    }

    if (NULL != node && kJoynetStatusConnected == node->status) {
        return 0;
    } else if (NULL != node && kJoynetStatusConnecting == node->status) {
        // 只能等待一次连接，因为getsockopt第二次调用不会返回正确的状态
        if (0 == joyClientCheckConnectByPoll_(node->cfd)) {
            if (0 != joyClientSetConnected_(node->cfd)) {
                debug_msg("error: fail to set connection to connected.");
                joyClientCloseTcp_(node->cfd);
                return -1;
            }
            return 0;
        } else {
            joyClientCloseTcp_(node->cfd);
            return -1;
        }
        if (tick <= node->createtick + kJoyClientConnectTimeOut) {
            return 0;
        }
        debug_msg("debug: connect timeout.");
        joyClientCloseTcp_(node->cfd);
    }
    debug_msg("debug: startting connect tcp.");

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == sockfd) {
        debug_msg("error: fail to create socket fd, errno[%s].", strerror(errno));
        return -1;
    }

    if (0 != joynetSetNoBlocking(sockfd)) {
        debug_msg("error: fail to set fd no blocking.");
        return -1;
    }

    if (0 != joynetSetTcpNoDelay(sockfd)) {
        debug_msg("error: fail to set fd no delay.");
        return -1;
    }

    if (0 != joynetSetTcpKeepAlive(sockfd)) {
        debug_msg("error: fail to set fd keep alive.");
        return -1;
    }
    int insertpost = joynetInsertConnectNode(&joyClient.cpool, sockfd);
    if (insertpost < 0) {
        debug_msg("error: fail to insert new node, fd[%d].", sockfd);
        return -1;
    }
    node = joyClient.cpool.node + insertpost;
    debug_msg("debug: insert node, fd[%d].", node->cfd);

    joynetSetSendBufSize(sockfd, kJoyClientSendBufSize);
    joynetSetRecvBufSize(sockfd, kJoyClientRecvBufSize);

    node->procid = procid;

    struct sockaddr_in servaddr;
    bzero(&servaddr,sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = inet_addr(addr);

    int rv = connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
    int connecterr = errno;
    debug_msg("debug: connect tcp, rv[%d], connecterr[%d][%s].", rv, connecterr, strerror(connecterr));
    if (-1 == rv) {
        if (EISCONN == connecterr) {
            //已经连接到该套接字
            if (0 != joyClientSetConnected_(node->cfd)) {
                debug_msg("error: fail to set connection to connected.");
                joyClientCloseTcp_(node->cfd);
                return -1;
            }
        } else if (EINPROGRESS == connecterr || EALREADY == connecterr) {
            /*
            ** EINPROGRESS: The socket is nonblocking and the connection cannot be completed immediately. It is possible to select(2) or
            ** poll(2) for completion by selecting the socket for writing.  After select(2) indicates  writability,  use  get‐
            ** sockopt(2)  to  read  the SO_ERROR option at level SOL_SOCKET to determine whether connect() completed success‐
            ** fully (SO_ERROR is zero) or unsuccessfully (SO_ERROR is one of the usual error codes  listed  here,  explaining
            ** the reason for the failure).
            ** EALREADY: The socket is nonblocking and a previous connection attempt has not yet been completed.
            ** 正在进行连接...
            */
            node->status = kJoynetStatusConnecting;
            debug_msg("debug: connect tcp connecterr[%s].", strerror(connecterr));
        } else {
            debug_msg("error: fail to connect addr[%s], port[%d], connecterr[%d][%s].", addr, port, connecterr, strerror(connecterr));
            joyClientCloseTcp_(node->cfd);
            return -1;
        }
    } else {
        if (0 != joyClientSetConnected_(node->cfd)) {
            debug_msg("error: fail to set connection to connected.");
            joyClientCloseTcp_(node->cfd);
            return -1;
        }
    }

    return 0;
}

int joyClientIsReady(int procid)
{
    int nodepos = joynetGetConnectNodePosByID(&joyClient.cpool, procid);
    if (nodepos < 0) {
        // debug_msg("error: fail to get node, procid[%d].", procid);
        return -1;
    }
    struct JoyConnectNode *node = joyClient.cpool.node + nodepos;
    return (node->status == kJoynetStatusConnected ? 1 : 0);
}

int joyClientProcRecvData()
{
    int totallen = 0;
    for (int i = 0; i < joyClient.cpool.nodes; ++i) {
        struct JoyConnectNode *node = joyClient.cpool.node + i;
        if (kJoynetStatusConnected != node->status) {
            continue;
        }
        unsigned int leftroom = joynetGetLeftRoom(&node->recvcq);
        if (leftroom <= 0) {
            debug_msg("warn: recv buf is full.");
            continue;
        }
        struct pollfd pfds[1];
        pfds[0].fd = node->cfd;
        pfds[0].events = POLLIN;
        int rv = poll(pfds, 1, kJoyClientPollTimeOut);
        if (rv < 0) {
            if (EINTR == errno) {
                continue;
            } else {
                debug_msg("error: errno[%s] when poll.", strerror(errno));
                joyClientCloseTcp_(node->cfd);
                continue;
            }
        } else if(0 == rv) {
            // debug_msg("info: time out poll.");
            continue;
        } else {
            if (pfds[0].events & POLLIN) {
                int rlen = joynetRecvBuf(node);
                if (rlen < 0) {
                    joyClientCloseTcp_(node->cfd);
                    continue;
                }
                totallen += rlen;
            }
        }
    }

    return totallen;
}

int joyClientRecvData(joyRecvCallBack recvCallBack)
{
    for (int i = 0; i < joyClient.cpool.nodes; ++i) {
        struct JoyConnectNode *node = joyClient.cpool.node + i;
        struct JoyCycleQueue *cq = &node->recvcq;
        while (sizeof(struct JoynetHead) <= cq->cnt) {
            struct JoynetHead pkghead;
            if (0 != joynetReadRecvBuf(node, (char *)(&pkghead), sizeof(struct JoynetHead))) {
                debug_msg("error: fail to read buf.");
                joyClientCloseTcp_(node->cfd);
                continue;
            }
            /* debug_msg("debug: headlen[%d], bodylen[%d] msgtype[%d], cnt[%d]", pkghead.headlen,
                 pkghead.bodylen, pkghead.msgtype, cq->cnt); */
            if (kJoynetMsgTypeShake == pkghead.msgtype) {
                node->procid = pkghead.srcid;
                // node->status = kJoynetStatusConnected;
                debug_msg("debug: shake hands success.");
                if (0 < pkghead.bodylen) {
                    debug_msg("error: invalid shake pkg.");
                    if (0 != joynetLeaveCycleQueue(cq, pkghead.bodylen)) {
                        debug_msg("error: fail to leave recv queue.");
                        joyClientCloseTcp_(node->cfd);
                    }
                }
            } else if (kJoynetMsgTypeMsg == pkghead.msgtype) {
                if (pkghead.bodylen <= cq->cnt) {
                    //处理包被落在队列两头的情况(基本不会出现)
                    if (cq->tail < cq->head && (cq->size - cq->head) < pkghead.bodylen) {
                        char *body = (char *)malloc(pkghead.bodylen);
                        if (NULL == body) {
                            debug_msg("error: fail to malloc, size[%d].", pkghead.bodylen);
                            joyClientCloseTcp_(node->cfd);
                        }
                        if (0 != joynetReadRecvBuf(node, body, pkghead.bodylen)) {
                            debug_msg("error: fail to read buf.");
                            joyClientCloseTcp_(node->cfd);
                        }
                        recvCallBack(body, &pkghead);
                        free(body);
                    } else {
                        char *body = node->recvbuf + cq->head;
                        recvCallBack(body, &pkghead);
                        if (0 != joynetLeaveCycleQueue(cq, pkghead.bodylen)) {
                            debug_msg("error: fail to leave recv queue.");
                            joyClientCloseTcp_(node->cfd);
                        }
                    }
                } else {
                    debug_msg("warn: body len not enough.");
                    continue;
                }
            } else {
                debug_msg("error: invalid msg type[%d].", pkghead.msgtype);
                joyClientCloseTcp_(node->cfd);
            }
        }
    }

    return joyClientProcRecvData();
}

int joyClientProcSendData()
{
    for (int i = 0; i < joyClient.cpool.nodes; ++i) {
        struct JoyConnectNode *node = joyClient.cpool.node + i;
        if (kJoynetStatusConnected != node->status) {
            continue;
        }
        if (joynetSendBuf(node) < 0) {
            debug_msg("error: fail to send buf, fd[%d].", node->cfd);
            joyClientCloseTcp_(node->cfd);
            continue;
        }
    }

    return 0;
}

static int joyClientSendPkg_(struct JoyConnectNode *node, const char *buf, const struct JoynetHead *pkghead)
{
    if (NULL == node || NULL == buf || NULL == pkghead) {
        debug_msg("error: invalid param, node[%p], buf[%p], pkghead[%p]", node, buf, pkghead);
        return -1;
    }

    int pkglen = pkghead->headlen + pkghead->bodylen;
    int leftroom = joynetGetLeftRoom(&node->sendcq);
    if (leftroom < pkglen) {
        debug_msg("error: leftlen[%d] is not enough, need len[%d].", leftroom, pkglen);
        return -1;
    }

    if (0 != joynetWriteSendBuf(node, (char *)(pkghead), pkghead->headlen)) {
        debug_msg("error: fail to write send buf.");
        joyClientCloseTcp_(node->cfd);
        return -1;
    }
    if (0 != joynetWriteSendBuf(node, buf, pkghead->bodylen)) {
        debug_msg("error: fail to write send buf.");
        joyClientCloseTcp_(node->cfd);
        return -1;
    }

    return 0;
}

int joyClientSendData(const char *buf, int len, int procid, int srcid, int dstid)
{
    if (NULL == buf || len <= 0) {
        debug_msg("error: invalid param, buf[%p], len[%d].", buf, len);
        return -1;
    }

    int nodepos = joynetGetConnectNodePosByID(&joyClient.cpool, procid);
    if (nodepos < 0) {
        debug_msg("error: fail to get node, procid[%d].", procid);
        return -1;
    }
    struct JoyConnectNode *node = joyClient.cpool.node + nodepos;
    if (kJoynetStatusConnected != node->status) {
        debug_msg("error: send to not connected id[%d].", dstid);
        return -1;
    }

    joyClientProcSendData();
    // 再次检查，可能在处理发送过程中发生错误，导致fd已关闭
    if (kJoynetStatusConnected != node->status) {
        debug_msg("error: send to not connected id[%d].", dstid);
        return -1;
    }

    struct JoynetHead pkghead = { 0 };
    if (0 != joynetMakePkgHead(&pkghead, buf, len, srcid, dstid, 0)) {
        debug_msg("error: fail to make pkg head.");
        return -1;
    }
    if (0 != joyClientSendPkg_(node, buf, &pkghead)) {
        debug_msg("error: fail to send pkg.");
        return -1;
    }

    joyClientProcSendData();

    return 0;
}

int joyClientSendDataByNid(const char *buf, int len, int procid, int srcid, int dstnid)
{
    if (NULL == buf || len <= 0) {
        debug_msg("error: invalid param, buf[%p], len[%d].", buf, len);
        return -1;
    }

    int nodepos = joynetGetConnectNodePosByID(&joyClient.cpool, procid);
    if (nodepos < 0) {
        debug_msg("error: fail to get node, procid[%d].", procid);
        return -1;
    }
    struct JoyConnectNode *node = joyClient.cpool.node + nodepos;
    if (kJoynetStatusConnected != node->status) {
        debug_msg("error: send to not connected nid[%d].", dstnid);
        return -1;
    }

    joyClientProcSendData();
    // 再次检查，可能在处理发送过程中发生错误，导致fd已关闭
    if (kJoynetStatusConnected != node->status) {
        debug_msg("error: send to not connected nid[%d].", dstnid);
        return -1;
    }

    struct JoynetHead pkghead = { 0 };
    if (0 != joynetMakePkgHead(&pkghead, buf, len, srcid, 0, dstnid)) {
        debug_msg("error: fail to make pkg head.");
        return -1;
    }
    if (0 != joyClientSendPkg_(node, buf, &pkghead)) {
        debug_msg("error: fail to send pkg.");
        return -1;
    }

    joyClientProcSendData();

    return 0;
}


int joyClientRegisterNid(int procid, int srcid, int nid)
{
    return 0;
}

/*
long int totalrecvlen;
static int clientRecvCallBack(char *buf, struct JoynetHead *pkghead)
{
    if (NULL == buf || NULL == pkghead) {
        debug_msg("error: invalid param, buf[%p], pkghead[%p]", buf, pkghead);
        return -1;
    }
    totalrecvlen += pkghead->bodylen;
    // debug_msg("recv head, msgtype[%d], headlen[%d], bodylen[%d], srcid[%d], dstid[%d], md5[%d].", \
        pkghead->msgtype, pkghead->headlen, pkghead->bodylen, pkghead->srcid, pkghead->dstid, pkghead->md5);
    // joyClientSendData(buf, pkghead->bodylen, pkghead->dstid, pkghead->srcid);
    return 0;
}

int main()
{
    // 压测
    time_t tick, now;
    time(&tick);
    char *test = "1234567890qwertyuioplkjhgfdsazxcvbnm,.;?";
    long int totallen = 0;
    int nodecnt = 512;
    int pkgcnt = 10;
    //连接
    for (int i = 0; i < nodecnt; ++i) {
        joyClientConnectTcp("127.0.0.1", 20000, i);
    }
    while (1) {
        time(&now);
        if (now < tick + 1) {
            continue;
        }
        tick = now;
        char allready = 1;
        for (int i = 0; i < nodecnt; ++i) {
            int nodepos = joynetGetConnectNodePosByID(&joyClient.cpool, i);
            if (nodepos < 0 || joyClient.cpool.node[nodepos].status != kJoynetStatusConnected) {
                joyClientConnectTcp("127.0.0.1", 20000, i);
                allready = 0;
            }
        }
        if (1 == allready) {
            break;
        }
    }
    //发包
    for (int i = 0; i < pkgcnt; ++i) {
        for (int j = 0; j < nodecnt; ++j) {
            int len = rand() % 39 + 1;
            joyClientSendData(test, len, j, j);
            joyClientRecvData(clientRecvCallBack);
            totallen += len;
        }
    }
    while(1){
        joyClientProcSendData();
        joyClientRecvData(clientRecvCallBack);
        time(&now);
        if (tick + 10 < now) {
            tick = now;
            break;
        }
    }
    debug_msg("total send len[%ld], recv len[%ld]", totallen, totalrecvlen);
    return 0;
}
*/

int main()
{
    return 0;
}
