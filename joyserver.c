#include <string.h>
#include <arpa/inet.h>
#include "joyserver.h"


static struct JoyServer joyServer;

int joyServerListen(const char *addr, int port)
{
    debug_msg("debug: listen tcp.");
    if (0 != joyServer.lfd) {
        debug_msg("warn: joyServer.lfd[%d] not equal to 0.", joyServer.lfd);
        joyServerCloseTcp(joyServer.lfd);
    }
    debug_msg("debug: startting listen tcp.");

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == sockfd) {
        debug_msg("error: fail to create socket fd, errno[%s].", strerror(errno));
        return -1;
    }
    joyServer.lfd = sockfd;

    if (0 != joynetSetNoBlocking(sockfd)) {
        debug_msg("error: fail to set fd no blocking.");
        return -1;
    }

    if (0 != joynetSetAddrReuse(sockfd)) {
        debug_msg("error: fail to set addr reuse.");
        return -1;
    }

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = inet_addr(addr);
    if (0 != bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))){
        debug_msg("error: fail to bind socket fd, addr[%s], port[%d], errno[%s].", addr, port, strerror(errno));
        return -1;
    }
    if (0 != listen(sockfd, kListenBacklog)) {
        debug_msg("error: fail to listen socket fd, errno[%s].", strerror(errno));
        return -1;
    }

    joyServer.efd = epoll_create(kEpollMaxFDs);
    if (joyServer.efd < 0) {
        debug_msg("fail to create epoll fd.");
        return -1;
    }
    struct epoll_event ev = { 0 };
    ev.events = EPOLLIN;
    ev.data.fd = sockfd;
    if (0 != epoll_ctl(joyServer.efd, EPOLL_CTL_ADD, sockfd, &ev)) {
        debug_msg("error: fail to epoll_ctl(EPOLL_CTL_ADD), sockfd[%d], errno[%s]", sockfd, strerror(errno));
    }

    return 0;
}

int joyServerCloseTcp(int fd)
{
    if (0 == fd) {
        debug_msg("error: invalid fd[%d].", fd);
        return -1;
    }

    struct epoll_event ev = { 0 };
    ev.data.fd = fd;
    if (0 != epoll_ctl(joyServer.efd, EPOLL_CTL_DEL, fd, &ev)) {
        debug_msg("fail to epoll_ctl(EPOLL_CTL_DEL), fd[%d], errno[%s]", fd, strerror(errno));
    }

    close(fd);
    if (fd == joyServer.lfd) {
        bzero(&joyServer, sizeof(joyServer));
    } else {
        if (0 != joynetDelConnectNode(&joyServer.cpool, fd)) {
            debug_msg("error: fail to del node, fd[%d].", fd);
        }
    }

    return 0;
}

int joyServerProcRecvData()
{
    struct epoll_event events[kEpollMaxFDs];
    int efdcnt = epoll_wait(joyServer.efd, events, kEpollMaxFDs, kJoyServerEpollTimeOut);
    if (efdcnt < 0) {
        if (EINTR == errno) {
            return 0;
        } else {
            debug_msg("error: errno[%s] when epoll.", strerror(errno));
            return -1;
        }
    } else if(0 == efdcnt) {
        // debug_msg("info: time out epoll.");
        return 0;
    } else {
        for (int i = 0; i < efdcnt; ++i) {
            if(events[i].data.fd == joyServer.lfd) {
                struct sockaddr_in clientaddr = { 0 };
                socklen_t clilen = sizeof(clientaddr);
                int connfd = accept(events[i].data.fd, (struct sockaddr *)&clientaddr, &clilen);
                if (connfd < 0) {
                    debug_msg("error: fail to accept, errno[%s].", strerror(errno));
                    continue;
                }
                debug_msg("debug: accept addr[%s], port[%d].", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port));
                if (0 != joynetSetNoBlocking(connfd)) {
                    debug_msg("error: fail to set fd no blocking.");
                    continue;
                }
                if (0 != joynetSetTcpNoDelay(connfd)) {
                    debug_msg("error: fail to set fd no delay.");
                    continue;
                }
                if (0 != joynetSetTcpKeepAlive(connfd)) {
                    debug_msg("error: fail to set fd keep alive.");
                    continue;
                }
                struct epoll_event ev = { 0 };
                ev.data.fd = connfd;
                ev.events = EPOLLIN;
                if (epoll_ctl(joyServer.efd, EPOLL_CTL_ADD, connfd, &ev)) {
                    debug_msg("fail to epoll_ctl(EPOLL_CTL_ADD), errno[%s].", strerror(errno));
                    joyServerCloseTcp(connfd);
                    continue;
                }
                joynetSetSendBufSize(connfd, kJoyServerSendBufSize);
                joynetSetRecvBufSize(connfd, kJoyServerRecvBufSize);
                int insertpos = joynetInsertConnectNode(&joyServer.cpool, connfd);
                if (insertpos < 0) {
                    joyServerCloseTcp(connfd);
                    continue;
                }
                struct JoyConnectNode *node = joyServer.cpool.node + insertpos;
                node->status = kJoynetStatusConnecting;
            } else if (events[i].events & EPOLLIN) {
                int infd = events[i].data.fd;
                int nodepos = joynetGetConnectNodePosByFD(&joyServer.cpool, infd);
                if (nodepos < 0) {
                    joyServerCloseTcp(infd);
                    continue;
                }
                struct JoyConnectNode *node = joyServer.cpool.node + nodepos;
                int rlen = joynetRecvBuf(node);
                if (rlen < 0) {
                    joyServerCloseTcp(infd);
                    continue;
                }
            }
        }
    }

    return 0;
}

int joyServerRecvData(joyRecvCallBack recvCallBack)
{
    for (int i = 0; i < joyServer.cpool.nodes; ++i) {
        struct JoyConnectNode *node = joyServer.cpool.node + i;
        struct JoyCycleQueue *cq = &node->recvcq;
        while (sizeof(struct JoynetHead) <= cq->cnt) {
            struct JoynetHead pkghead;
            if (0 != joynetReadRecvBuf(node, (char *)(&pkghead), sizeof(struct JoynetHead))) {
                debug_msg("error: fail to read buf.");
                joyServerCloseTcp(node->cfd);
                continue;
            }
            if (kJoynetMsgTypeShake == pkghead.msgtype) {
                node->procid = pkghead.srcid;
                node->status = kJoynetStatusConnected;
                debug_msg("debug: shake hands success.");
                if (0 < pkghead.bodylen) {
                    debug_msg("error: invalid shake pkg.");
                    if (joynetLeaveCycleQueue(cq, pkghead.bodylen)) {
                        debug_msg("error: fail to leave recv queue.");
                        joyServerCloseTcp(node->cfd);
                    }
                }
            } else if (kJoynetMsgTypeMsg == pkghead.msgtype) {
                if (pkghead.bodylen <= cq->cnt) {
                    //处理包被落在队列两头的情况(基本不会出现)
                    if (cq->tail < cq->head && (cq->size - cq->head) < pkghead.bodylen) {
                        char *body = (char *)malloc(pkghead.bodylen);
                        if (NULL == body) {
                            debug_msg("error: fail to malloc, size[%d].", pkghead.bodylen);
                            joyServerCloseTcp(node->cfd);
                        }
                        if (0 != joynetReadRecvBuf(node, body, pkghead.bodylen)) {
                            debug_msg("error: fail to read buf.");
                            joyServerCloseTcp(node->cfd);
                        }
                        recvCallBack(body, &pkghead);
                        free(body);
                    } else {
                        char *body = node->recvbuf + cq->head;
                        recvCallBack(body, &pkghead);
                        if (joynetLeaveCycleQueue(cq, pkghead.bodylen)) {
                            debug_msg("error: fail to leave recv queue.");
                            joyServerCloseTcp(node->cfd);
                        }
                    }
                } else {
                    debug_msg("warn: body len not enough.");
                    continue;
                }
            } else {
                debug_msg("error: invalid msg type[%d].", pkghead.msgtype);
                joyServerCloseTcp(node->cfd);
            }
        }
    }

    int rv = joyServerProcRecvData();
    if (rv < 0) {
        debug_msg("error: fail to recv data.");
        return -1;
    }

    return 0;
}

int joyServerProcSendData()
{
    for (int i = 0; i < joyServer.cpool.nodes; ++i) {
        struct JoyConnectNode *node = joyServer.cpool.node + i;
        if (kJoynetStatusConnected != node->status) {
            continue;
        }
        if (joynetSendBuf(node) < 0) {
            debug_msg("error: fail to send buf.");
            joyServerCloseTcp(node->cfd);
            continue;
        }
    }

    return 0;
}

int joyServerSendData(const char *buf, int len, int srcid, int dstid)
{
    if (NULL == buf || len <= 0) {
        debug_msg("error: invalid param, buf[%p], len[%d].", buf, len);
        return -1;
    }

    int nodepos = joynetGetConnectNodePosByID(&joyServer.cpool, dstid);
    if (nodepos < 0) {
        debug_msg("error: fail to get node, procid[%d].", dstid);
        return -1;
    }
    struct JoyConnectNode *node = joyServer.cpool.node + nodepos;
    if (kJoynetStatusConnected != node->status) {
        debug_msg("error: send to not connected id[%d].", dstid);
        return -1;
    }

    joyServerProcSendData();
    // 再次检查，可能在处理发送过程中发生错误，导致fd已关闭
    if (kJoynetStatusConnected != node->status) {
        debug_msg("error: send to not connected id[%d].", dstid);
        return -1;
    }

    struct JoynetHead pkghead = { 0 };
    pkghead.headlen = sizeof(pkghead);
    pkghead.bodylen = len;
    pkghead.srcid = srcid;
    pkghead.dstid = dstid;
    pkghead.md5 = 0;

    int pkglen = pkghead.headlen + pkghead.bodylen;
    int leftroom = joynetGetLeftRoom(&node->sendcq);
    if (leftroom < pkglen) {
        debug_msg("error: leftlen[%d] is not enough, need len[%d].", leftroom, pkglen);
        return -1;
    }

    if (0 != joynetWriteSendBuf(node, (char *)(&pkghead), pkghead.headlen)) {
        debug_msg("error: fail to write send buf.");
        joyServerCloseTcp(node->cfd);
        return -1;
    }
    if (0 != joynetWriteSendBuf(node, buf, pkghead.bodylen)) {
        debug_msg("error: fail to write send buf.");
        joyServerCloseTcp(node->cfd);
        return -1;
    }

    joyServerProcSendData();

    return 0;
}

static int serverRecvCallBack(char *buf, struct JoynetHead *pkghead)
{
    if (NULL == buf || NULL == pkghead) {
        debug_msg("error: invalid param, buf[%p], pkghead[%p]", buf, pkghead);
        return -1;
    }
    debug_msg("recv head, msgtype[%d], headlen[%d], bodylen[%d], srcid[%d], dstid[%d], md5[%d].", \
        pkghead->msgtype, pkghead->headlen, pkghead->bodylen, pkghead->srcid, pkghead->dstid, pkghead->md5);
    joyServerSendData(buf, pkghead->bodylen, pkghead->dstid, pkghead->srcid);
    return 0;
}

int main()
{
    if (0 != joyServerListen("0.0.0.0", 20000)) {
        return -1;
    }
    while (1) {
        joyServerRecvData(serverRecvCallBack);
    }
    return 0;
}