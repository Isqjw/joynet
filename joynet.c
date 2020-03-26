#include "joynet.h"

int joynetSetNoBlocking(int fd)
{
    int flags;
    if ((flags = fcntl(fd, F_GETFL)) == -1) {
        debug_msg("error: fail to fcntl(F_GETFL).");
        return -1;
    }
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1) {
        debug_msg("error: fail to fcntl(F_SETFL).");
        return -1;
    }
    return 0;
}

int joynetSetTcpNoDelay(int fd)
{
    int yes = 1;
    if (-1 == setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes))) {
        debug_msg("error: fail to setsockopt(TCP_NODELAY), errno[%s].", strerror(errno));
        return -1;
    }
    return 0;
}

int joynetSetTcpKeepAlive(int fd)
{
    int yes = 1;
    if (-1 == setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) == -1) {
        debug_msg("error: fail to setsockopt(SO_KEEPALIVE), errno[%s].", strerror(errno));
        return -1;
    }
    return 0;
}

int joynetSetAddrReuse(int fd)
{
    int yes = 1;
    if (-1 == setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
        debug_msg("error: fail to setsockopt(SO_REUSEADDR), errno[%s].", strerror(errno));
        return -1;
    }
    return 0;
}

int joynetSetSendBufSize(int sockfd, unsigned int bufsize)
{
    return setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
}

int joynetSetRecvBufSize(int sockfd, unsigned int bufsize)
{
    return setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
}

int joynetSend(int fd, const char *buf, int len, int to)
{
    if (NULL == buf || len <= 0) {
        debug_msg("invalid param, buf[%p], len[%d].", buf, len);
        return -1;
    }
    int slen = send(fd, buf, len, to);
    if (slen < 0) {
        /*
        ** EAGAIN, EWOULDBLOCK 非阻塞情况下发送缓存已满
        ** send超时为0, 可以不处理EINTR中断错误
        */
        if (EINTR == errno || EAGAIN == errno || EWOULDBLOCK == errno) {
            return 0;
        }
        debug_msg("error: send errno[%s].", strerror(errno));
        return -1;
    } else if (0 == slen) {
        debug_msg("error: connect already closed.");
        return -1;
    }
    return slen;
}

int joynetRecv(int fd, char *buf, int len, int to)
{
    if (NULL == buf || len <= 0) {
        debug_msg("invalid param, buf[%p], len[%d].", buf, len);
        return -1;
    }
    int rlen = recv(fd, buf, len, to);
    if (rlen < 0) {
        /*
        ** 对非阻塞socket而言，EAGAIN不是一种错误。在VxWorks和Windows上，EAGAIN的名字叫做EWOULDBLOCK
        ** 另外，如果出现EINTR即errno为4，错误描述Interrupted system call，操作也应该继续
        ** recv超时为0, 可以不处理EINTR中断错误
        */
        if (EINTR == errno || EAGAIN == errno || EWOULDBLOCK == errno) {
            return 0;
        }
        debug_msg("error: recv errno[%s].", strerror(errno));
        return -1;
    } else if (0 == rlen) {
        debug_msg("error: connect already closed.");
        return -1;
    }
    return rlen;
}

int joynetSendBuf(struct JoyConnectNode* node)
{
    if (NULL == node) {
        debug_msg("error: invalid param, node[%p].", node);
        return -1;
    }
    if (node->sendcq.cnt <= 0) {
        //没有数据可发送
        return 0;
    }
    int sendcnt = node->sendcq.tail < node->sendcq.head ? 2 : 1;
    if (node->sendcq.tail == node->sendcq.head) {
        sendcnt = 0 == node->sendcq.head ? 1 : 2;
    }
    int sTotalLen = 0;
    for (int i = 0; i < sendcnt && 0 < node->sendcq.cnt; ++i) {
        int callen = 0;     //计算发送长度(考虑head==tail的情况)
        if (node->sendcq.tail <= node->sendcq.head) {
            callen = node->sendcq.size - node->sendcq.head;
        } else {
            callen = node->sendcq.tail - node->sendcq.head;
        }
        int slen = joynetSend(node->cfd, node->sendbuf + node->sendcq.head, callen, 0);
        if (slen < 0) {
            debug_msg("error: fail to send buf.");
            return -1;
        }
        if (0 != joynetLeaveCycleQueue(&node->sendcq, slen)) {
            debug_msg("error: fail to leave queue.");
            return -1;
        }
        sTotalLen += slen;
    }
    debug_msg("debug: send msg len[%d].", sTotalLen);
    return sTotalLen;
}

int joynetRecvBuf(struct JoyConnectNode* node)
{
    if (NULL == node) {
        debug_msg("error: invalid param, node[%p].", node);
        return -1;
    }
    int leftroom = joynetGetLeftRoom(&node->recvcq);
    if (leftroom <= 0) {
        //没有空间接收数据
        return 0;
    }
    int recvcnt = node->recvcq.tail < node->recvcq.head ? 1 : 2;
    if (node->recvcq.tail == node->recvcq.head) {
        recvcnt = 0 == node->recvcq.tail ? 1 : 2;
    }
    int rTotalLen = 0;
    for (int i = 0; i < recvcnt; ++i) {
        int callen = 0;     //计算发送长度(考虑head==tail的情况)
        if (node->recvcq.tail < node->recvcq.head) {
            callen = node->recvcq.head - node->recvcq.tail;
        } else {
            callen = node->recvcq.size - node->recvcq.tail;
        }
        int rlen = joynetRecv(node->cfd, node->recvbuf + node->recvcq.tail, callen, 0);
        if (rlen < 0) {
            debug_msg("error: fail to recv buf.");
            return -1;
        }
        if (0 != joynetEnterCycleQueue(&node->recvcq, rlen)) {
            debug_msg("error: fail to enter queue.");
            return -1;
        }
        rTotalLen += rlen;
    }
    debug_msg("debug: recv msg len[%d].", rTotalLen);
    return rTotalLen;
}

int joynetWriteSendBuf(struct JoyConnectNode *node, const char *buf, int len)
{
    if (NULL == node || NULL == buf || len <= 0) {
        debug_msg("error: invalid param, node[%p], buf[%p], len[%d].", node, buf, len);
        return -1;
    }
    struct JoyCycleQueue *cq = &node->sendcq;
    int leftroom = joynetGetLeftRoom(cq);
    if (leftroom < len) {
        debug_msg("error: left room[%d] not enough, send len[%d].", leftroom, len);
        return -1;
    }
    if (cq->head < cq->tail) {
        if (cq->size - cq->tail < len) {
            int firstlen = cq->size - cq->tail;
            int secondlen = len - firstlen;
            memcpy(node->sendbuf + cq->tail, buf, firstlen);
            memcpy(node->sendbuf, buf + firstlen, secondlen);
            debug_msg("warn: write separation data, [%d]-[%d], [%d]-[%d]", cq->tail, cq->size, 0, secondlen);
        } else {
            memcpy(node->sendbuf + cq->tail, buf, len);
        }
    } else {
        memcpy(node->sendbuf + cq->tail, buf, len);
    }
    joynetEnterCycleQueue(cq, len);
    return 0;
}

int joynetReadRecvBuf(struct JoyConnectNode *node, char *buf, int len)
{
    if (NULL == node || NULL == buf || len <= 0) {
        debug_msg("error: invalid param, node[%p], buf[%p], len[%d].", node, buf, len);
        return -1;
    }
    struct JoyCycleQueue *cq = &node->recvcq;
    if (cq->cnt < len) {
        debug_msg("error: data cnt[%d] not enough, read len[%d].", cq->cnt, len);
        return -1;
    }
    if (cq->tail < cq->head) {
        if (cq->size - cq->head < len) {
            int firstlen = cq->size - cq->head;
            int secondlen = len - firstlen;
            memcpy(buf, node->recvbuf + cq->head, firstlen);
            memcpy(buf + firstlen, node->recvbuf, secondlen);
            debug_msg("warn: read separation data, [%d]-[%d], [%d]-[%d]", cq->head, cq->size, 0, secondlen);
        } else {
            memcpy(buf, node->recvbuf + cq->head, len);
        }
    } else {
        memcpy(buf, node->recvbuf + cq->head, len);
    }
    joynetLeaveCycleQueue(cq, len);
    return 0;
}

int joynetGetConnectNodePosByFD(struct JoyConnectPool *cp, int cfd)
{
    if (NULL == cp) {
        debug_msg("error: invalid param cp[%p].\n", cp);
        return -1;
    }
    for (int i = 0; i < cp->nodes; ++i) {
        if (cfd == cp->node[i].cfd) {
            return i;
        }
    }
    return -1;
}

int joynetGetConnectNodePosByID(struct JoyConnectPool *cp, int id)
{
    if (NULL == cp) {
        debug_msg("error: invalid param cp[%p].\n", cp);
        return -1;
    }
    for (int i = 0; i < cp->nodes; ++i) {
        if (id == cp->node[i].procid) {
            return i;
        }
    }
    return -1;
}

int joynetDelConnectNode(struct JoyConnectPool *cp, int cfd)
{
    if (NULL == cp) {
        debug_msg("error: invalid param cp[%p].\n", cp);
        return -1;
    }
    int pos = joynetGetConnectNodePosByFD(cp, cfd);
    if (pos < 0) {
        return -1;
    }
    if (NULL != cp->node[pos].sendbuf) {
        free(cp->node[pos].sendbuf);
    }
    if (NULL != cp->node[pos].recvbuf) {
        free(cp->node[pos].recvbuf);
    }
    bzero(cp->node + pos, sizeof(struct JoyConnectNode));
    if (cp->nodes - 1 == pos) {
        //pass
    } else {
        int movesize = (cp->nodes - pos - 1) * sizeof(struct JoyConnectNode);
        memmove(cp->node + pos, cp->node + pos + 1, movesize);
    }
    cp->nodes--;
    return 0;
}

int joynetInsertConnectNode(struct JoyConnectPool *cp, int cfd)
{
    if (NULL == cp) {
        debug_msg("error: invalid param cp[%p].\n", cp);
        return -1;
    }
    int pos = joynetGetConnectNodePosByFD(cp, cfd);
    if (0 <= pos) {
        debug_msg("error: node already exist.");
        return -1;
    }
    int lastpos = cp->nodes;
    if (kEpollMaxFDs <= lastpos) {
        debug_msg("error: connect pool is full.");
        return -1;
    }
    char *sendbuf = (char *)malloc(kJoynetSendBufSize);
    if (NULL == sendbuf) {
        debug_msg("error: fail to malloc.");
        return -1;
    }
    char *recvbuf = (char *)malloc(kJoynetRecvBufSize);
    if (NULL == recvbuf) {
        free(sendbuf);
        debug_msg("error: fail to malloc.");
        return -1;
    }
    time_t tick;
    time(&tick);
    bzero(cp->node + lastpos, sizeof(struct JoyConnectNode));
    cp->node[lastpos].cfd = cfd;
    cp->node[lastpos].sendbuf = sendbuf;
    cp->node[lastpos].sendcq.size = kJoynetSendBufSize;
    cp->node[lastpos].recvbuf = recvbuf;
    cp->node[lastpos].recvcq.size = kJoynetRecvBufSize;
    cp->node[lastpos].createtick = tick;
    cp->nodes++;
    return lastpos;
}

int joynetEnterCycleQueue(struct JoyCycleQueue *cq, int len)
{
    if (NULL == cq) {
        debug_msg("error: invalid param, cq[%p].", cq);
        return -1;
    }
    int leftroom = cq->size - cq->cnt;
    if (leftroom < len) {
        debug_msg("error: room not enough, left room[%d], len[%d].", leftroom, len);
        return -1;
    }
    cq->tail = (cq->tail + len) % cq->size;
    cq->cnt += len;
    return 0;
}

int joynetLeaveCycleQueue(struct JoyCycleQueue *cq, int len)
{
    if (NULL == cq) {
        debug_msg("error: invalid param, cq[%p].", cq);
        return -1;
    }
    if (cq->cnt < len) {
        debug_msg("error: leave len[%d] bigger than user len[%d].", len, cq->cnt);
        return -1;
    }
    cq->head = (cq->head + len) % cq->size;
    cq->cnt -= len;
    //特殊处理(尽量保证数据不会出现在队列两头)
    if (0 == cq->cnt) {
        cq->head = 0;
        cq->tail = 0;
    }
    return 0;
}

int joynetGetLeftRoom(struct JoyCycleQueue *cq)
{
    if (NULL == cq) {
        debug_msg("error: invalid param, cq[%p].", cq);
        return -1;
    }
    return cq->size - cq->cnt;
}