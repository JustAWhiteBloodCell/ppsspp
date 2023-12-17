#pragma once

enum SocketOptions {
    // TODO: also specify minimum socket size
    SCE_SO_ACCEPTCONN   = 0x0002, // socket has had listen()
    SCE_SO_REUSEADDR    = 0x0004, // allow local address reuse
    SCE_SO_KEEPALIVE    = 0x0008, // keep connections alive
    SCE_SO_DONTROUTE    = 0x0010, // just use interface addresses
    SCE_SO_BROADCAST    = 0x0020, // permit sending of broadcast msgs
    SCE_SO_USELOOPBACK  = 0x0040, // bypass hardware when possible
    SCE_SO_LINGER       = 0x0080, // linger on close if data present
    SCE_SO_OOBINLINE    = 0x0100, // leave received OOB data in line
    SCE_SO_REUSEPORT    = 0x0200, // allow local address & port reuse
    SCE_SO_TIMESTAMP    = 0x0400, // timestamp received dgram traffic
    SCE_SO_ONESBCAST    = 0x0800, // allow broadcast to 255.255.255.255
    SCE_SO_SNDBUF       = 0x1001, // send buffer size
    SCE_SO_RCVBUF       = 0x1002, // receive buffer size
    SCE_SO_SNDLOWAT     = 0x1003, // send low-water mark
    SCE_SO_RCVLOWAT     = 0x1004, // receive low-water mark
    SCE_SO_SNDTIMEO     = 0x1005, // send timeout
    SCE_SO_RCVTIMEO     = 0x1006, // receive timeout
    SCE_SO_ERROR        = 0x1007, // get error status and clear
    SCE_SO_TYPE         = 0x1008, // get socket type
    SCE_SO_OVERFLOWED   = 0x1009, // datagrams: return packets dropped
    SCE_SO_NONBLOCK     = 0x1009, // non-blocking I/O
};

class SceSocket {
public:
    SceSocket(int sceSocketId, int nativeSocketId) : m_sceSocketId(sceSocketId), m_nativeSocketId(nativeSocketId) {}

    int GetSceSocketId() const {
        return m_sceSocketId;
    }

    // TODO: rename
    int GetNativeSocketId() const {
        return m_nativeSocketId;
    }

    bool GetNonBlocking() const {
        return m_nonBlocking;
    }

    void SetNonBlocking(const bool nonBlocking) {
        m_nonBlocking = nonBlocking;
    }
private:
    int m_sceSocketId;
    int m_nativeSocketId;
    bool m_nonBlocking = false;
};
