// Copyright (c) 2012- PPSSPP Project.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 2.0 or later versions.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License 2.0 for more details.

// A copy of the GPL 2.0 should have been included with the program.
// If not, see http://www.gnu.org/licenses/

// Official git repository and contact information can be found at
// https://github.com/hrydgard/ppsspp and http://www.ppsspp.org/.

#if __linux__ || __APPLE__ || defined(__OpenBSD__)
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#endif

#include "Common/Net/Resolve.h"
#include "Common/Data/Text/Parsers.h"

#include "Common/Serialize/Serializer.h"
#include "Common/Serialize/SerializeFuncs.h"
#include "Core/Config.h"
#include "Core/HLE/HLE.h"
#include "Core/HLE/FunctionWrappers.h"
#include "Core/MIPS/MIPS.h"
#include "Core/MemMapHelpers.h"

#include "Core/HLE/proAdhoc.h"
#include "Core/HLE/sceNet.h"
#include "Core/HLE/sceNetInet.h"

#include <iostream>
#include <shared_mutex>

#include "Core/HLE/sceNp.h"
#include "Core/Reporting.h"
// TODO: move Core/Net
#include "Core/Net/InetCommon.h"
#include "Core/Net/SceSocket.h"

#if PPSSPP_PLATFORM(SWITCH) && !defined(INADDR_NONE)
// Missing toolchain define
#define INADDR_NONE 0xFFFFFFFF
#elif PPSSPP_PLATFORM(WINDOWS)
#pragma comment(lib, "ws2_32.lib")
#define close closesocket
#define ERROR_WHEN_NONBLOCKING_CALL_OCCURS WSAEWOULDBLOCK
using netBufferType = char;
#else
#define ERROR_WHEN_NONBLOCKING_CALL_OCCURS EAGAIN
#include <ifaddrs.h>
using netBufferType = void;
#endif

static int getLastError() {
#if PPSSPP_PLATFORM(WINDOWS)
	return WSAGetLastError();
#else
	return errno;
#endif
}

static int sceNetInetInit() {
    ERROR_LOG(SCENET, "UNTESTED sceNetInetInit()");
    return SceNetInet::Init() ? 0 : ERROR_NET_INET_ALREADY_INITIALIZED;
}

int sceNetInetTerm() {
    ERROR_LOG(SCENET, "UNTESTED sceNetInetTerm()");
	SceNetInet::Shutdown();
    return 0;
}

static int sceNetInetInetAton(const char *hostname, u32 addrPtr) {
	ERROR_LOG(SCENET, "UNTESTED sceNetInetInetAton(%s, %08x)", hostname, addrPtr);
	if (!Memory::IsValidAddress(addrPtr)) {
		ERROR_LOG(SCENET, "sceNetInetInetAton: Invalid addrPtr: %08x", addrPtr);
		return -1;
	}

	in_addr inAddr{};
#if PPSSPP_PLATFORM(WINDOWS)
	const int ret = inet_pton(AF_INET, hostname, &inAddr);
#else
	const int ret = inet_aton(hostname, &inAddr);
#endif
	if (ret != 0)
		Memory::Write_U32(inAddr.s_addr, addrPtr);
	return ret;
}

static u32 sceNetInetInetAddr(const char *hostname) {
	ERROR_LOG(SCENET, "UNTESTED sceNetInetInetAddr(%s)", hostname);
	in_addr inAddr{};
	// TODO: de-dupe
#if PPSSPP_PLATFORM(WINDOWS)
	const int ret = inet_pton(AF_INET, hostname, &inAddr);
#else
	const int ret = inet_aton(hostname, &inAddr);
#endif
	if (ret != 0)
		return inAddr.s_addr;
	return ret;
}

static bool sceSockaddrToNativeSocketAddr(sockaddr_in& dest, u32 sockAddrInternetPtr, size_t addressLength) {
	const auto sceNetSockaddrIn = Memory::GetTypedPointerRange<SceNetInetSockaddrIn>(sockAddrInternetPtr, addressLength);
	if (sceNetSockaddrIn == nullptr || addressLength == 0) {
		return false;
	}

	memset(&dest, 0, sizeof(dest));
	dest.sin_family = sceNetSockaddrIn->sin_family;
	dest.sin_port = sceNetSockaddrIn->sin_port;
	dest.sin_addr.s_addr = sceNetSockaddrIn->sin_addr;
	DEBUG_LOG(SCENET, "sceSockaddrToNativeSocketAddr: Family %i, port %i, addr %s, len %i", dest.sin_family, ntohs(dest.sin_port), ip2str(dest.sin_addr, false).c_str(), sceNetSockaddrIn->sin_len);
	return true;
}

static bool writeSockAddrInToSceSockAddr(u32 destAddrPtr, u32 destAddrLenPtr, sockaddr_in src) {
	const auto sceNetSocklen = reinterpret_cast<u32*>(Memory::GetPointerWrite(destAddrLenPtr));
	if (sceNetSocklen == nullptr) {
		return false;
	}
	const auto sceNetSockaddrIn = Memory::GetTypedPointerWriteRange<SceNetInetSockaddrIn>(destAddrPtr, *sceNetSocklen);
	if (sceNetSockaddrIn == nullptr) {
		return false;
	}
	INFO_LOG(SCENET, "writeSockAddrInToSceSockAddr: %lu vs %i", sizeof(SceNetInetSockaddrIn), *sceNetSocklen);
	*sceNetSocklen = std::min<u32>(*sceNetSocklen, sizeof(SceNetInetSockaddr));
	// TODO: re-evaluate len field
	if (*sceNetSocklen >= 1) {
		sceNetSockaddrIn->sin_len = *sceNetSocklen;
	}
	if (*sceNetSocklen >= 2) {
		sceNetSockaddrIn->sin_family = src.sin_family;
	}
	if (*sceNetSocklen >= 4) {
		sceNetSockaddrIn->sin_port = src.sin_port;
	}
	if (*sceNetSocklen >= 8) {
		sceNetSockaddrIn->sin_addr = src.sin_addr.s_addr;
	}
	return true;
}

static int setBlockingMode(int fd, bool nonblocking) {
#if PPSSPP_PLATFORM(WINDOWS)
	unsigned long val = nonblocking ? 1 : 0;
	return ioctlsocket(fd, FIONBIO, &val);
#else
	// Change to Non-Blocking Mode
	if (nonblocking) {
		return fcntl(fd, F_SETFL, O_NONBLOCK);
	} else {
		const int flags = fcntl(fd, F_GETFL);

		// Remove Non-Blocking Flag
		return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
	}
#endif
}

static int sceNetInetGetsockname(int socket, u32 addrPtr, u32 addrLenPtr) {
	ERROR_LOG(SCENET, "UNTESTED sceNetInetGetsockname(%i, %08x, %08x)", socket, addrPtr, addrLenPtr);
	const auto sceNetInet = SceNetInet::Get();
	if (!sceNetInet) {
		return hleLogError(SCENET, ERROR_NET_INET_CONFIG_INVALID_ARG, "Inet Subsystem Not Running - Use sceNetInetInit");
	}

	int nativeSocketId;
	if (!sceNetInet->GetNativeSocketIdForSceSocketId(nativeSocketId, socket)) {
		ERROR_LOG(SCENET, "sceNetInetGetsockname: Requested socket %i which does not exist", socket);
		return -1;
	}

	sockaddr_in sockaddrIn{};
	socklen_t socklen = sizeof(sockaddr_in);
	const int ret = getsockname(nativeSocketId, reinterpret_cast<sockaddr*>(&sockaddrIn), &socklen);
	if (ret < 0) {
		const auto error = getLastError();
		ERROR_LOG(SCENET, "[%i] sceNetInetGetsockname: Failed to execute getsockname %i: %s", nativeSocketId, error, strerror(error));
		return ret;
	}

	if (!writeSockAddrInToSceSockAddr(addrPtr, addrLenPtr, sockaddrIn)) {
		ERROR_LOG(SCENET, "[%i] sceNetInetGetsockname: Failed to write results of getsockname to SceNetInetSockaddrIn", nativeSocketId);
		return -1;
	}
	return ret;
}

static int sceNetInetGetErrno() {
	ERROR_LOG_ONCE(sceNetInetGetErrno, SCENET, "UNTESTED sceNetInetGetErrno()");
	const auto error = getLastError();
	if (error != ERROR_WHEN_NONBLOCKING_CALL_OCCURS && error != 0) {
		INFO_LOG(SCENET, "Requested sceNetInetGetErrno %i=%s", error, strerror(error));
	}
	switch (error) {
		case ETIMEDOUT:
			return INET_ETIMEDOUT;
		case EISCONN:
			return INET_EISCONN;
#if PPSSPP_PLATFORM(WINDOWS)
		case EINPROGRESS:
			return INET_EAGAIN;
#else
		case EINPROGRESS:
			return INET_EINPROGRESS;
#endif
	}
	return error; //-1;
}

int sceNetInetPoll(void* fds, u32 nfds, int timeout) { // timeout in miliseconds
	DEBUG_LOG(SCENET, "UNTESTED sceNetInetPoll(%p, %d, %i) at %08x", fds, nfds, timeout, currentMIPS->pc);
	const auto fdarray = static_cast<SceNetInetPollfd*>(fds); // SceNetInetPollfd/pollfd, sceNetInetPoll() have similarity to BSD poll() but pollfd have different size on 64bit
//#ifdef _WIN32
	//WSAPoll only available for Vista or newer, so we'll use an alternative way for XP since Windows doesn't have poll function like *NIX
	if (nfds > FD_SETSIZE) {
		ERROR_LOG(SCENET, "sceNetInetPoll: nfds=%i is greater than FD_SETSIZE=%i, unable to poll", nfds, FD_SETSIZE);
		return -1;
	}
	fd_set readfds, writefds, exceptfds;
	FD_ZERO(&readfds); FD_ZERO(&writefds); FD_ZERO(&exceptfds);
	for (int i = 0; i < static_cast<s32>(nfds); i++) {
		if (fdarray[i].events & (INET_POLLRDNORM))
			FD_SET(fdarray[i].fd, &readfds); // (POLLRDNORM | POLLIN)
		if (fdarray[i].events & (INET_POLLWRNORM))
			FD_SET(fdarray[i].fd, &writefds); // (POLLWRNORM | POLLOUT)
		//if (fdarray[i].events & (ADHOC_EV_ALERT)) // (POLLRDBAND | POLLPRI) // POLLERR
		FD_SET(fdarray[i].fd, &exceptfds);
		fdarray[i].revents = 0;
	}
	timeval tmout{};
	tmout.tv_sec = timeout / 1000; // seconds
	tmout.tv_usec = (timeout % 1000) * 1000; // microseconds
	const int ret = select(nfds, &readfds, &writefds, &exceptfds, &tmout);
	if (ret < 0)
		return -1;
	int eventCount = 0;
	for (int i = 0; i < static_cast<s32>(nfds); i++) {
		if (FD_ISSET(fdarray[i].fd, &readfds))
			fdarray[i].revents |= INET_POLLRDNORM; //POLLIN
		if (FD_ISSET(fdarray[i].fd, &writefds))
			fdarray[i].revents |= INET_POLLWRNORM; //POLLOUT
		fdarray[i].revents &= fdarray[i].events;
		if (FD_ISSET(fdarray[i].fd, &exceptfds))
			fdarray[i].revents |= ADHOC_EV_ALERT; // POLLPRI; // POLLERR; // can be raised on revents regardless of events bitmask?
		if (fdarray[i].revents)
			eventCount++;
	}
//#else
	/*
	// Doesn't work properly yet
	pollfd *fdtmp = (pollfd *)malloc(sizeof(pollfd) * nfds);
	// Note: sizeof(pollfd) = 16bytes in 64bit and 8bytes in 32bit, while sizeof(SceNetInetPollfd) is always 8bytes
	for (int i = 0; i < (s32)nfds; i++) {
		fdtmp[i].fd = fdarray[i].fd;
		fdtmp[i].events = 0;
		if (fdarray[i].events & INET_POLLRDNORM) fdtmp[i].events |= (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI);
		if (fdarray[i].events & INET_POLLWRNORM) fdtmp[i].events |= (POLLOUT | POLLWRNORM | POLLWRBAND);
		fdtmp[i].revents = 0;
		fdarray[i].revents = 0;
	}
	retval = poll(fdtmp, (nfds_t)nfds, timeout); //retval = WSAPoll(fdarray, nfds, timeout);
	for (int i = 0; i < (s32)nfds; i++) {
		if (fdtmp[i].revents & (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) fdarray[i].revents |= INET_POLLRDNORM;
		if (fdtmp[i].revents & (POLLOUT | POLLWRNORM | POLLWRBAND)) fdarray[i].revents |= INET_POLLWRNORM;
		fdarray[i].revents &= fdarray[i].events;
		if (fdtmp[i].revents & POLLERR) fdarray[i].revents |= POLLERR; //INET_POLLERR // can be raised on revents regardless of events bitmask?
	}
	free(fdtmp);
	*/
//#endif
	return eventCount;
}

#if PPSSPP_PLATFORM(WINDOWS)
// Windows has fewer max FDs than other platforms so we can use it directly
#define __fd_mask uint32_t
#define	__NBBY	8				/* number of bits in a byte */
#define __NFDBITS ((unsigned)(sizeof(__fd_mask) * __NBBY)) /* bits per mask */
#endif

typedef struct
{
	__fd_mask  fds_bits[256 / __NFDBITS];
} sce_fd_set;
# define __SCE_FDS_BITS(set) ((set)->fds_bits)
/* We don't use `memset' because this would require a prototype and
   the array isn't too big.  */
#define	__SCE_FD_ELT(d)	((d) / __NFDBITS)
#define	__SCE_FD_MASK(d)	((__fd_mask) (1UL << ((d) % __NFDBITS)))
#define __SCE_FD_ZERO(s) \
do {									      \
unsigned int __i;							      \
fd_set *__arr = (s);						      \
for (__i = 0; __i < sizeof (fd_set) / sizeof (__fd_mask); ++__i)	      \
__SCE_FDS_BITS (__arr)[__i] = 0;					      \
} while (0)
#define __SCE_FD_SET(d, s) \
((void) (__SCE_FDS_BITS (s)[__SCE_FD_ELT(d)] |= __SCE_FD_MASK(d)))
#define __SCE_FD_CLR(d, s) \
((void) (__SCE_FDS_BITS (s)[__SCE_FD_ELT(d)] &= ~__SCE_FD_MASK(d)))
#define __SCE_FD_ISSET(d, s) \
((__SCE_FDS_BITS (s)[__SCE_FD_ELT (d)] & __SCE_FD_MASK (d)) != 0)
#define	SCE_FD_SET(fd, fdsetp)	__SCE_FD_SET (fd, fdsetp)
#define	SCE_FD_CLR(fd, fdsetp)	__SCE_FD_CLR (fd, fdsetp)
#define	SCE_FD_ISSET(fd, fdsetp)	__SCE_FD_ISSET (fd, fdsetp)
#define	SCE_FD_ZERO(fdsetp)		__SCE_FD_ZERO (fdsetp)

struct sce_timeval {
	u32 tv_sec;		/* Seconds.  */
	u32 tv_usec;	/* Microseconds.  */
};

bool SceNetInet::translateSceFdSetToNativeFdSet(int& maxFd, fd_set& destFdSet, u32 fdsPtr) const {
	if (fdsPtr == 0) {
		// Allow nullptr to be used without failing
		return true;
	}

	FD_ZERO(&destFdSet);
	const auto sceFdSet = Memory::GetTypedPointerRange<sce_fd_set>(fdsPtr, sizeof(sce_fd_set));
	if (sceFdSet == nullptr) {
		ERROR_LOG(SCENET, "%s: Invalid fdsPtr %08x", __func__, fdsPtr);
		return false;
	}

	int setSize = 0;
	for (auto& it : m_sceSocketIdToNativeSocket) {
		const auto sceSocket = it.first;
		auto fd = it.second->GetNativeSocketId();
		if (fd + 1 > maxFd) {
			maxFd = fd + 1;
		}
		if (SCE_FD_ISSET(sceSocket, sceFdSet)) {
			if (++setSize > FD_SETSIZE) {
				ERROR_LOG(SCENET, "%s: Encountered input FD_SET which is greater than max supported size %i", __func__, setSize);
				return false;
			}
			DEBUG_LOG(SCENET, "%s: Translating input %i into %i", __func__, sceSocket, fd);
			FD_SET(fd, &destFdSet);
		}
	}

	DEBUG_LOG(SCENET, "%s: Translated %i sockets", __func__, setSize);
	return true;
}

void SceNetInet::CloseAllRemainingSockets() const {
	for (auto& it : m_sceSocketIdToNativeSocket) {
		if (!it.second)
			continue;
		close(it.second->GetNativeSocketId());
	}
}

static int sceNetInetSelect(int maxfd, u32 readFdsPtr, u32 writeFdsPtr, u32 exceptFdsPtr, u32 timeoutPtr) {
	WARN_LOG_ONCE(sceNetInetSelect, SCENET, "UNTESTED sceNetInetSelect(%i, %08x, %08x, %08x, %08x)", maxfd, readFdsPtr, writeFdsPtr, exceptFdsPtr, timeoutPtr);
	const auto sceNetInet = SceNetInet::Get();
	if (!sceNetInet) {
		return hleLogError(SCENET, ERROR_NET_INET_CONFIG_INVALID_ARG, "Inet Subsystem Not Running - Use sceNetInetInit");
	}

	int recomputedMaxFd = 1;
	fd_set readFds;
	sceNetInet->translateSceFdSetToNativeFdSet(recomputedMaxFd, readFds, readFdsPtr);
	fd_set writeFds;
	sceNetInet->translateSceFdSetToNativeFdSet(recomputedMaxFd, writeFds, writeFdsPtr);
	fd_set exceptFds;
	sceNetInet->translateSceFdSetToNativeFdSet(recomputedMaxFd, exceptFds, exceptFdsPtr);

	timeval tv{};
	if (timeoutPtr != 0) {
		const auto sceTimeval = Memory::GetTypedPointerRange<sce_timeval>(timeoutPtr, sizeof(sce_timeval));
		if (sceTimeval != nullptr) {
			tv.tv_sec = sceTimeval->tv_sec;
			tv.tv_usec = sceTimeval->tv_usec;
			DEBUG_LOG(SCENET, "sceNetInetSelect: Timeout seconds=%lu, useconds=%lu", tv.tv_sec, tv.tv_usec);
		} else {
			WARN_LOG(SCENET, "sceNetInetSelect: Encountered invalid timeout value, continuing anyway");
		}
	}

	const int ret = select(recomputedMaxFd,  readFdsPtr != 0 ? &readFds : nullptr, writeFdsPtr != 0 ? &writeFds : nullptr,  exceptFdsPtr != 0 ? &exceptFds : nullptr, timeoutPtr != 0 ? &tv : nullptr);
	if (ret < 0) {
		const auto error = getLastError();
		ERROR_LOG(SCENET, "sceNetInetSelect: Received error from select() %i: %s", error, strerror(error));
	}

	INFO_LOG(SCENET, "sceNetInetSelect: select() returned %i", ret);
	return hleDelayResult(ret, "TODO: unhack", 300);
}

static int sceNetInetClose(int socket) {
	const auto sceNetInet = SceNetInet::Get();
	if (!sceNetInet) {
		return hleLogError(SCENET, ERROR_NET_INET_CONFIG_INVALID_ARG, "Inet Subsystem Not Running - Use sceNetInetInit");
	}

	const auto sceSocket = sceNetInet->GetSceSocket(socket);
	if (!sceSocket) {
		WARN_LOG(SCENET, "sceNetInetClose: Attempting to close socket %i which does not exist", socket);
		return -1;
	}

	const int ret = close(sceSocket->GetNativeSocketId());
	if (!sceNetInet->EraseNativeSocket(socket)) {
		ERROR_LOG(SCENET, "sceNetInetClose: Unable to clear mapping of sceSocketId->nativeSocketId, was there contention?");
		return -1;
	}

	return ret;
}

static int sceNetInetRecv(int socket, u32 bufPtr, u32 bufLen, int flags) {
	WARN_LOG_ONCE(sceNetInetRecv, SCENET, "UNTESTED sceNetInetRecv(%i, %08x, %i, %08x)", socket, bufPtr, bufLen, flags);
	const auto sceNetInet = SceNetInet::Get();
	if (!sceNetInet) {
		return hleLogError(SCENET, ERROR_NET_INET_CONFIG_INVALID_ARG, "Inet Subsystem Not Running - Use sceNetInetInit");
	}

	auto sceSocket = sceNetInet->GetSceSocket(socket);
	if (!sceSocket) {
		WARN_LOG(SCENET, "sceNetInetClose: Attempting to close socket %i which does not exist", socket);
		return -1;
	}

	const auto dstBuf = Memory::GetTypedPointerWriteRange<netBufferType>(bufPtr, bufLen);
	if (dstBuf == nullptr) {
		return hleLogError(SCENET, ERROR_NET_INET_INVALID_ARG, "sceNetInetRecv: Invalid pointer %08x (size %i)", bufPtr, bufLen);
	}

	const int ret = recv(sceSocket->GetNativeSocketId(), dstBuf, bufLen, flags);
	if (ret < 0) {
		const auto error = getLastError();
		if (error != ERROR_WHEN_NONBLOCKING_CALL_OCCURS)
			ERROR_LOG(SCENET, "[%i]: %s: recv() encountered error %i: %s", socket, __func__, error, strerror(error));
	}
	return ret;
}

static int sceNetInetRecvfrom(int socket, u32 bufPtr, u32 bufLen, int flags, u32 fromAddr, u32 fromLenAddr) {
	WARN_LOG_ONCE(sceNetInetRecvFrom, SCENET, "UNTESTED sceNetInetRecvfrom(%i, %08x, %i, %08x, %08x, %08x)", socket, bufPtr, bufLen, flags, fromAddr, fromLenAddr);
	const auto sceNetInet = SceNetInet::Get();
	if (!sceNetInet) {
		return hleLogError(SCENET, ERROR_NET_INET_CONFIG_INVALID_ARG, "Inet Subsystem Not Running - Use sceNetInetInit");
	}

	const auto sceSocket = sceNetInet->GetSceSocket(socket);
	if (!sceSocket) {
		ERROR_LOG(SCENET, "sceNetInetRecvfrom: Attempting to operate on unmapped socket %i", socket);
		return -1;
	}

#if PPSSPP_PLATFORM(LINUX)
	if (sceSocket->GetNonBlocking()) {
		flags |= MSG_DONTWAIT;
	}
#endif

	DEBUG_LOG(SCENET, "sceNetInetRecvfrom(%i, %08x, %i, %08x, %08x, %08x)", socket, bufPtr, bufLen, flags, fromAddr, fromLenAddr);

	auto fd = sceSocket->GetNativeSocketId();
	sockaddr_in sockaddrIn{};
	socklen_t socklen = sizeof(sockaddr_in);
	const auto dstBuf = Memory::GetTypedPointerWriteRange<netBufferType>(bufPtr, bufLen);
	if (dstBuf == nullptr) {
		ERROR_LOG(SCENET, "[%i] sceNetInetRecvfrom: Invalid pointer range: %08x (size %i)", socket, bufPtr, bufLen);
		return -1;
	}

	Memory::Memset(bufPtr, 0, bufLen, "sceNetInetRecvfrom");
	const int ret = recvfrom(fd, dstBuf, bufLen, flags, reinterpret_cast<sockaddr*>(&sockaddrIn), &socklen);

	if (ret < 0) {
		const auto error = getLastError();
		// TODO: winsockify
		if (error != 0 && error != ERROR_WHEN_NONBLOCKING_CALL_OCCURS) {
			WARN_LOG(SCENET, "[%i] sceNetInetRecvfrom: Received error %i: %s", fd, error, strerror(error));
		}
		return hleDelayResult(ret, "TODO: unhack", 160);
	}

	if (ret > 0) {
		if (!writeSockAddrInToSceSockAddr(fromAddr, fromLenAddr, sockaddrIn)) {
			ERROR_LOG(SCENET, "[%i] sceNetInetRecvfrom: Error writing native sockaddr to sceSockaddr", fd);
		}
		INFO_LOG(SCENET, "[%i] sceNetInetRecvfrom: Got %i bytes from recvfrom", fd, ret);
	}
	return hleDelayResult(ret, "TODO: unhack", 160);
}

static int sceNetInetSend(int socket, u32 bufPtr, u32 bufLen, u32 flags) {
	WARN_LOG_ONCE(sceNetInetSend, SCENET, "UNTESTED sceNetInetSend(%i, %08x, %i, %08x)", socket, bufPtr, bufLen, flags);
	const auto sceNetInet = SceNetInet::Get();
	if (!sceNetInet) {
		return hleLogError(SCENET, ERROR_NET_INET_CONFIG_INVALID_ARG, "Inet Subsystem Not Running - Use sceNetInetInit");
	}

	const auto sceSocket = sceNetInet->GetSceSocket(socket);
	if (!sceSocket) {
		ERROR_LOG(SCENET, "%s: Attempting to operate on unmapped socket %i", __func__, socket);
		return -1;
	}

	const auto resolvedPtr = Memory::GetTypedPointerRange<netBufferType>(bufPtr, bufLen);
	if (resolvedPtr == nullptr) {
		ERROR_LOG(SCENET, "[%i] %s: Invalid pointer range: %08x (size %i)", socket, __func__, bufPtr, bufLen);
		return -1;
	}

	const int ret = send(sceSocket->GetNativeSocketId(), resolvedPtr, bufLen, flags);
	if (ret < 0) {
		const auto error = getLastError();
		ERROR_LOG(SCENET, "[%i]: %s: send() encountered error %i: %s", socket, __func__, error, strerror(error));
	}

	return ret;
}

static int sceNetInetSendto(int socket, u32 bufPtr, u32 bufLen, u32 flags, u32 toAddr, u32 toLen) {
	ERROR_LOG_ONCE(sceNetInetSendto, SCENET, "UNTESTED sceNetInetSendto(%i, %08x, %i, %08x, %08x, %i)", socket, bufPtr, bufLen, flags, toAddr, toLen);
	// WARN_LOG(SCENET, "UNIMPL sceNetInetSendto(%i, %08x, %i, %08x, %08x, %i)", socket, bufPtr, bufLen, flags, toAddr, toLen);
	// return 0;
	const auto sceNetInet = SceNetInet::Get();
	if (!sceNetInet) {
		return hleLogError(SCENET, ERROR_NET_INET_CONFIG_INVALID_ARG, "Inet Subsystem Not Running - Use sceNetInetInit");
	}

	const auto sceSocket = sceNetInet->GetSceSocket(socket);
	if (!sceSocket) {
		ERROR_LOG(SCENET, "sceNetInetSendto: Attempting to operate on unmapped socket %i", socket);
		return -1;
	}

	auto fd = sceSocket->GetNativeSocketId();

	// TODO: validatd socket
	// TODO: validated ptr
	const auto srcBuf = Memory::GetTypedPointerRange<netBufferType>(bufPtr, bufLen);
	if (srcBuf == nullptr) {
		ERROR_LOG(SCENET, "[%i] sceNetInetSendto: Invalid pointer range: %08x (size %i)", socket, bufPtr, bufLen);
		return -1;
	}

	sockaddr_in convertedSockAddr{};
	if (!sceSockaddrToNativeSocketAddr(convertedSockAddr, toAddr, toLen)) {
		ERROR_LOG(SCENET, "[%i] sceNetInetSendto: Unable to translate sceSockAddr to native sockaddr", fd);
		return -1;
	}

	DEBUG_LOG(SCENET, "[%i] sceNetInetSendto: Writing %i bytes to %s on port %i", fd, bufLen, ip2str(convertedSockAddr.sin_addr, false).c_str(), ntohs(convertedSockAddr.sin_port));

#if PPSSPP_PLATFORM(LINUX)
	if (sceSocket->GetNonBlocking()) {
		flags |= MSG_DONTWAIT;
	}
#endif

	const int ret = sendto(fd, srcBuf, bufLen, flags, reinterpret_cast<sockaddr*>(&convertedSockAddr), sizeof(sockaddr_in));
	DEBUG_LOG(SCENET, "[%i] sceNetInetSendto: sendto returned %i", fd, ret);

	if (ret < 0) {
		const auto error = getLastError();
		WARN_LOG(SCENET, "[%i] sceNetInetSendto: Got error %i=%s", fd, error, strerror(error));
	}

	return ret;
}

static int sceNetInetBind(int socket, u32 addrPtr, u32 addrLen) {
	WARN_LOG_ONCE(sceNetInetSend, SCENET, "UNTESTED sceNetInetBind(%i, %08x, %08x)", socket, addrPtr, addrLen);
	const auto sceNetInet = SceNetInet::Get();
	if (!sceNetInet) {
		return hleLogError(SCENET, ERROR_NET_INET_CONFIG_INVALID_ARG, "Inet Subsystem Not Running - Use sceNetInetInit");
	}

	int nativeSocketId;
	if (!sceNetInet->GetNativeSocketIdForSceSocketId(nativeSocketId, socket)) {
		ERROR_LOG(SCENET, "sceNetInetBind: Attempting to operate on unmapped socket %i", socket);
		return -1;
	}

#if PPSSPP_PLATFORM(LINUX)
	// Set broadcast
	// TODO: move broadcast SceSocket
	int broadcastEnabled = 1;
	int sockoptRet = setsockopt(nativeSocketId, SOL_SOCKET, SO_BROADCAST, &broadcastEnabled, sizeof(broadcastEnabled));

	// Set reuseport / reuseaddr by default
	// TODO: evaluate
	int opt = 1;
#if defined(SO_REUSEPORT)
	setsockopt(nativeSocketId, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
	setsockopt(nativeSocketId, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#elif PPSSPP_PLATFORM(WINDOWS)
	// Set broadcast
	// TODO: move broadcast SceSocket
	int broadcastEnabled = 1;
	int sockoptRet = setsockopt(nativeSocketId, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<char*>(&broadcastEnabled), sizeof(broadcastEnabled));
	int opt = 1;
	setsockopt(nativeSocketId, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char*>(&opt), sizeof(opt));
#endif

	sockaddr_in convertedSockaddr{};
	if (!sceSockaddrToNativeSocketAddr(convertedSockaddr, addrPtr, addrLen)) {
		ERROR_LOG(SCENET, "[%i] Error translating sceSockaddr to native sockaddr", nativeSocketId);
		return -1;
	}
	socklen_t socklen = sizeof(convertedSockaddr);
	if (!getDefaultOutboundSockaddr(convertedSockaddr, socklen)) {
		WARN_LOG(SCENET, "Failed to get default bound address");
		return -1;
	}
	INFO_LOG(SCENET, "[%i] Binding to family %i, port %i, addr %s sockoptRet %i", nativeSocketId, convertedSockaddr.sin_family, ntohs(convertedSockaddr.sin_port), ip2str(convertedSockaddr.sin_addr, false).c_str(), sockoptRet);
	const int ret = bind(nativeSocketId, reinterpret_cast<sockaddr*>(&convertedSockaddr), socklen);
	INFO_LOG(SCENET, "Bind returned %i for fd=%i", ret, nativeSocketId);
	return ret;
}

static int sceNetInetSocket(int domain, int type, int protocol) {
	ERROR_LOG(SCENET, "UNTESTED sceNetInetSocket(%i, %i, %i)", domain, type, protocol);
	auto sceNetInet = SceNetInet::Get();
	if (!sceNetInet) {
		return hleLogError(SCENET, ERROR_NET_INET_CONFIG_INVALID_ARG, "Inet Subsystem Not Running - Use sceNetInetInit");
	}

	const int nativeSocketId = socket(domain, type, protocol);
	const auto sceSocket = sceNetInet->CreateAndAssociateNativeSocket(nativeSocketId);

	if (!sceSocket) {
		close(nativeSocketId);
		return hleLogError(SCENET, ERROR_NET_INET_INVALID_ARG, "%s: Unable to create new SceSocket for native socket id %i, closing");
	}

	return sceSocket->GetSceSocketId();
}

static int setsockopt_u32(const std::shared_ptr<SceSocket>& sceSocket, int level, int optname, u32 optval) {
	const auto nativeSocketId = sceSocket->GetNativeSocketId();
	INFO_LOG(SCENET, "[%i] setsockopt_u32(%i, %i, %i, %i)", nativeSocketId, nativeSocketId, level, optname, optval);
	switch (optname) {
		case SCE_SO_BROADCAST: {
			INFO_LOG(SCENET, "UNTESTED SCE_SO_BROADCAST sceNetInetSetsockopt(%i, %i, %i, %u, %i)", nativeSocketId, level, optname, optval, 4);
			int ret = setsockopt(nativeSocketId, SOL_SOCKET, optname, reinterpret_cast<netBufferType*>(&optval), sizeof(optval));
			if (ret < 0) {
				const auto error = getLastError();
				INFO_LOG(SCENET, "setsockopt_u32: Got error %i: %s on socket %i", error, strerror(error), nativeSocketId);
			} else {
				INFO_LOG(SCENET, "setsockopt_u32: setsockopt returned %i for %i", ret, nativeSocketId);
			}
			return 0;
		}
		case SCE_SO_ERROR: {
			// Proxy to SO_ERROR
			return setsockopt_u32(sceSocket, level, SO_ERROR, optval);
		}
		case SCE_SO_NONBLOCK: {
			const bool nonblocking = optval != 0;
			sceSocket->SetNonBlocking(nonblocking);
			INFO_LOG(SCENET, "[%i] setsockopt_u32: Set non-blocking=%i", nativeSocketId, nonblocking);
			if (setBlockingMode(nativeSocketId, nonblocking) != 0) {
				const auto error = getLastError();
				ERROR_LOG(SCENET, "[%i] Failed to set to non-blocking: %i: %s", nativeSocketId, error, strerror(error));
			}
			return 0;
		}
		default: {
			INFO_LOG(SCENET, "UNTESTED sceNetInetSetsockopt(%i, %i, %i, %u, %i)", nativeSocketId, level, optname, optval, 4);
			int ret = setsockopt(nativeSocketId, SOL_SOCKET, optname, reinterpret_cast<netBufferType*>(&optval), sizeof(optval));
			INFO_LOG(SCENET, "setsockopt_u32: setsockopt returned %i for %i", ret, nativeSocketId);
			return ret;
		}
	}
}

static int sceNetInetSetsockopt(int socket, int level, int optname, u32 optvalPtr, int optlen) {
	WARN_LOG(SCENET, "UNTESTED sceNetInetSetsockopt(%i, %i, %i, %08x, %i)", socket, level, optname, optvalPtr, optlen);
	const auto sceNetInet = SceNetInet::Get();
	if (!sceNetInet) {
		return hleLogError(SCENET, ERROR_NET_INET_CONFIG_INVALID_ARG, "Inet Subsystem Not Running - Use sceNetInetInit");
	}

	const auto sceSocket = sceNetInet->GetSceSocket(socket);
	if (!sceSocket) {
		ERROR_LOG(SCENET, "sceNetInetSetsockopt: Attempting to operate on unmapped socket %i", socket);
		return -1;
	}
	
	switch (optlen) {
		case sizeof(u32): {
			return setsockopt_u32(sceSocket, level, optname, Memory::Read_U32(optvalPtr));
		}
		default: {
			ERROR_LOG(SCENET, "UNIMPL sceNetInetSetsockopt(%i, %i, %i, %08x, %i)", socket, level, optname, optvalPtr, 4);
		}
	}
	
	return -1;
}

static int sceNetInetGetsockopt(int socket, int level, int optname, u32 optvalPtr, u32 optlenPtr) {
	WARN_LOG(SCENET, "UNTESTED sceNetInetGetsockopt(%i, %i, %i, %08x, %08x)", socket, level, optname, optvalPtr, optlenPtr);
	const auto sceNetInet = SceNetInet::Get();
	if (!sceNetInet) {
		return hleLogError(SCENET, ERROR_NET_INET_CONFIG_INVALID_ARG, "Inet Subsystem Not Running - Use sceNetInetInit");
	}

	const auto sceSocket = sceNetInet->GetSceSocket(socket);
	if (!sceSocket) {
		ERROR_LOG(SCENET, "sceNetInetGetsockopt: Attempting to operate on unmapped socket %i", socket);
		return -1;
	}

	// TODO: implement non-blocking
	const auto fd = sceSocket->GetNativeSocketId();

#if PPSSPP_PLATFORM(WINDOWS)
	auto optlen = reinterpret_cast<int*>(Memory::GetPointerWrite(optlenPtr));
#else
	auto optlen = reinterpret_cast<u32*>(Memory::GetPointerWrite(optlenPtr));
#endif
	if (optlen == nullptr) {
		ERROR_LOG(SCENET, "[%i] sceNetInetGetsockopt: Invalid pointer %08x", fd, optlenPtr);
		return -1;
	}

	const auto optval = Memory::GetTypedPointerWriteRange<netBufferType>(optvalPtr, *optlen);
	if (optval == nullptr) {
		ERROR_LOG(SCENET, "[%i] sceNetInetGetsockopt: Invalid pointer range %08x (size %i)", fd, optvalPtr, *optlen);
		return -1;
	}

	switch (optname) {
		case SCE_SO_ERROR: {
			optname = SO_ERROR;
			INFO_LOG(SCENET, "[%i] Re-writing optname=%04x to %04x", fd, SCE_SO_ERROR, SO_ERROR);
			break;
		}
	}

	const int ret = getsockopt(fd, SOL_SOCKET, optname, optval, optlen);
	if (ret < 0) {
		const auto error = getLastError();
		ERROR_LOG(SCENET, "[%i] sceNetInetGetsockopt returned error %i: %s", fd, error, strerror(error));
	}

	return ret;
}

static int sceNetInetConnect(int socket, u32 sockAddrInternetPtr, int addressLength) {
	ERROR_LOG(SCENET, "UNTESTED sceNetInetConnect(%i, %08x, %i, %i)", socket, sockAddrInternetPtr, Memory::Read_U32(sockAddrInternetPtr), addressLength);
	auto sceNetInet = SceNetInet::Get();
	if (!sceNetInet)
		return hleLogError(SCENET, ERROR_NET_INET_CONFIG_INVALID_ARG, "Inet Subsystem Not Running - Use sceNetInetInit");

	int nativeSocket;
	if (!sceNetInet->GetNativeSocketIdForSceSocketId(nativeSocket, socket)) {
		ERROR_LOG(SCENET, "sceNetInetConnect: Attempting to operate on unmapped socket %i", socket);
		return -1;
	}
	
	// TODO: bounds check etc

	sockaddr_in convertedSockaddr{};
	if (!sceSockaddrToNativeSocketAddr(convertedSockaddr, sockAddrInternetPtr, addressLength)) {
		ERROR_LOG(SCENET, "[%i] sceNetInetConnect: Error translating sceSockaddr to native sockaddr", socket);
		return -1;
	}

	DEBUG_LOG(SCENET, "[%i] sceNetInetConnect: Connecting to %s on %i", nativeSocket, ip2str(convertedSockaddr.sin_addr, false).c_str(), ntohs(convertedSockaddr.sin_port));

	int ret = connect(nativeSocket, reinterpret_cast<sockaddr*>(&convertedSockaddr), sizeof(convertedSockaddr));
	if (ret < 0) {
		const auto error = getLastError();
		INFO_LOG(SCENET, "[%i] sceNetInetConnect: Encountered error %i: %s", nativeSocket, error, strerror(error));
	}
	return ret;
}

const HLEFunction sceNetInet[] = {
	{0X17943399, &WrapI_V<sceNetInetInit>,           "sceNetInetInit",                  'i', ""     },
	{0X4CFE4E56, nullptr,                            "sceNetInetShutdown",              '?', ""     },
	{0XA9ED66B9, &WrapI_V<sceNetInetTerm>,           "sceNetInetTerm",                  'i', ""     },
	{0X8B7B220F, &WrapI_III<sceNetInetSocket>,       "sceNetInetSocket",                'i', "iii"  },
	{0X2FE71FE7, &WrapI_IIIUI<sceNetInetSetsockopt>, "sceNetInetSetsockopt",            'i', "iiixi"},
	{0X4A114C7C, &WrapI_IIIUU<sceNetInetGetsockopt>,  "sceNetInetGetsockopt",            'i', "iiixx"},
	{0X410B34AA, &WrapI_IUI<sceNetInetConnect>,      "sceNetInetConnect",               'i', "ixi"  },
	{0X805502DD, nullptr,                            "sceNetInetCloseWithRST",          '?', ""     },
	{0XD10A1A7A, nullptr,                            "sceNetInetListen",                '?', ""     },
	{0XDB094E1B, nullptr,                            "sceNetInetAccept",                '?', ""     },
	{0XFAABB1DD, &WrapI_VUI<sceNetInetPoll>,         "sceNetInetPoll",                  'i', "pxi"  },
	{0X5BE8D595, &WrapI_IUUUU<sceNetInetSelect>,               "sceNetInetSelect",                'i', "ixxxx"     },
	{0X8D7284EA, &WrapI_I<sceNetInetClose>,          "sceNetInetClose",                 '?', ""     },
	{0XCDA85C99, &WrapI_IUUI<sceNetInetRecv>,        "sceNetInetRecv",                  'i', "ixxi" },
	{0XC91142E4, &WrapI_IUUIUU<sceNetInetRecvfrom>,  "sceNetInetRecvfrom",              'i', "ixxxxx"},
	{0XEECE61D2, nullptr,                            "sceNetInetRecvmsg",               '?', ""     },
	{0X7AA671BC, &WrapI_IUUU<sceNetInetSend>,        "sceNetInetSend",                  'i', "ixxx" },
	{0X05038FC7, &WrapI_IUUUUU<sceNetInetSendto>,    "sceNetInetSendto",                'i', "ixxxxx"},
	{0X774E36F4, nullptr,                            "sceNetInetSendmsg",               '?', ""     },
	{0XFBABE411, &WrapI_V<sceNetInetGetErrno>,       "sceNetInetGetErrno",              'i', ""     },
	{0X1A33F9AE, &WrapI_IUU<sceNetInetBind>,         "sceNetInetBind",                  'i', ""     },
	{0XB75D5B0A, &WrapU_C<sceNetInetInetAddr>,          "sceNetInetInetAddr",              'u', "p"     },
	{0X1BDF5D13, &WrapI_CU<sceNetInetInetAton>,      "sceNetInetInetAton",              'i', "sx"   },
	{0XD0792666, nullptr,                            "sceNetInetInetNtop",              '?', ""     },
	{0XE30B8C19, nullptr,                            "sceNetInetInetPton",              '?', ""     },
	{0X8CA3A97E, nullptr,                            "sceNetInetGetPspError",           '?', ""     },
	{0XE247B6D6, nullptr,                            "sceNetInetGetpeername",           '?', ""     },
	{0X162E6FD5, &WrapI_IUU<sceNetInetGetsockname>,                     "sceNetInetGetsockname",           '?', ""     },
	{0X80A21ABD, nullptr,                            "sceNetInetSocketAbort",           '?', ""     },
	{0X39B0C7D3, nullptr,                            "sceNetInetGetUdpcbstat",          '?', ""     },
	{0XB3888AD4, nullptr,                            "sceNetInetGetTcpcbstat",          '?', ""     },
};

std::shared_ptr<SceNetInet> SceNetInet::g_instance;
std::shared_mutex SceNetInet::g_lock;

bool SceNetInet::Init() {
	auto lock = std::unique_lock(g_lock);
	if (g_instance)
		return false;
	g_instance = std::make_shared<SceNetInet>();
	return true;
}

bool SceNetInet::Shutdown() {
	auto lock = std::unique_lock(g_lock);
	if (!g_instance)
		return false;
	g_instance->CloseAllRemainingSockets();
	g_instance = nullptr;
	return true;
}

std::shared_ptr<SceSocket> SceNetInet::CreateAndAssociateNativeSocket(int nativeSocketId) {
	auto lock = std::unique_lock(m_lock);

	int sceSocketId = ++m_sceSocketId;
	const auto it = m_sceSocketIdToNativeSocket.find(sceSocketId);
	if (it != m_sceSocketIdToNativeSocket.end()) {
		WARN_LOG(SCENET, "%s: Attempted to re-associate socket from already-associated sceSocketId: %i", __func__, sceSocketId);
		return nullptr;
	}
	auto sceSocket = std::make_shared<SceSocket>(sceSocketId, nativeSocketId);
	m_sceSocketIdToNativeSocket.emplace(sceSocketId, sceSocket);
	return sceSocket;
}

std::shared_ptr<SceSocket> SceNetInet::GetSceSocket(int sceSocketId) {
	auto lock = std::shared_lock(m_lock);

	const auto it = m_sceSocketIdToNativeSocket.find(sceSocketId);
	if (it == m_sceSocketIdToNativeSocket.end()) {
		WARN_LOG(SCENET, "%s: Attempted to get unassociated socket from sceSocketId: %i", __func__, sceSocketId);
		return nullptr;
	}

	return it->second;
}

bool SceNetInet::GetNativeSocketIdForSceSocketId(int& nativeSocketId, int sceSocketId) {
	const auto sceSocket = GetSceSocket(sceSocketId);
	if (!sceSocket)
		return false;
	nativeSocketId = sceSocket->GetNativeSocketId();
	return true;
}

bool SceNetInet::EraseNativeSocket(int sceSocketId) {
	auto lock = std::unique_lock(m_lock);

	const auto it = m_sceSocketIdToNativeSocket.find(sceSocketId);
	if (it == m_sceSocketIdToNativeSocket.end()) {
		WARN_LOG(SCENET, "%s: Attempted to delete unassociated socket from sceSocketId: %i", __func__, sceSocketId);
		return false;
	}
	m_sceSocketIdToNativeSocket.erase(it);
	return true;
}

void Register_sceNetInet() {
	RegisterModule("sceNetInet", ARRAY_SIZE(sceNetInet), sceNetInet);
}
