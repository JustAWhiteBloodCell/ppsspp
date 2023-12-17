#pragma once

#include "Core/HLE/HLE.h"
#include "Core/Net/SceSocket.h"

#if PPSSPP_PLATFORM(WINDOWS)
#include <winsock.h>
#endif

#include <memory>
#include <shared_mutex>
#include <unordered_map>


enum {
    // pspnet_inet
    ERROR_NET_INET_ALREADY_INITIALIZED		= 0x80410201,
    ERROR_NET_INET_SOCKET_BUSY				= 0x80410202,
    ERROR_NET_INET_CONFIG_INVALID_ARG		= 0x80410203,
    ERROR_NET_INET_GET_IFADDR				= 0x80410204,
    ERROR_NET_INET_SET_IFADDR				= 0x80410205,
    ERROR_NET_INET_DEL_IFADDR				= 0x80410206,
    ERROR_NET_INET_NO_DEFAULT_ROUTE			= 0x80410207,
    ERROR_NET_INET_GET_ROUTE				= 0x80410208,
    ERROR_NET_INET_SET_ROUTE				= 0x80410209,
    ERROR_NET_INET_FLUSH_ROUTE				= 0x8041020a,
    ERROR_NET_INET_INVALID_ARG				= 0x8041020b,
};

class SceNetInet {
public:
    static bool Init();
    static bool Shutdown();
    static std::shared_ptr<SceNetInet> Get() {
        return g_instance;
    }

    // TODO: name native socket, maybe SceSocket ?
    std::shared_ptr<SceSocket> CreateAndAssociateNativeSocket(int nativeSocketId);
    std::shared_ptr<SceSocket> GetSceSocket(int sceSocketId);
    bool GetNativeSocketIdForSceSocketId(int& nativeSocketId, int sceSocketId);
    bool EraseNativeSocket(int sceSocketId);

    // TODO: use bool
    bool translateSceFdSetToNativeFdSet(int& maxFd, fd_set& destFdSet, u32 fdsPtr) const;

private:
    void CloseAllRemainingSockets() const;

    static std::shared_ptr<SceNetInet> g_instance;
    static std::shared_mutex g_lock;

    std::unordered_map<int, std::shared_ptr<SceSocket>> m_sceSocketIdToNativeSocket;
    int m_sceSocketId = 0;
    std::shared_mutex m_lock;
};

void Register_sceNetInet();
