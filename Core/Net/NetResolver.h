#pragma once

#include "CommonTypes.h"

class NetResolver {
public:
    NetResolver(const NetResolver& other) :
        id(other.id),
        isRunning(other.isRunning),
        bufferAddr(other.bufferAddr),
        bufferLen(other.bufferLen) {}

    NetResolver() :
        id(0),
        isRunning(false),
        bufferAddr(0),
        bufferLen(0) {}

    NetResolver(const int id, const u32 bufferAddr, const int bufferLen) :
        id(id),
        isRunning(false),
        bufferAddr(bufferAddr),
        bufferLen(bufferLen) {}

    int GetId() const { return id; }

    bool GetIsRunning() const { return isRunning; }

    void SetIsRunning(const bool isRunning) { this->isRunning = isRunning; }

private:
    int id;
    bool isRunning;
    u32 bufferAddr;
    u32 bufferLen;
};
