#pragma once

#include <string>
#include <array>
#include <cctype>
#include <cstdint>

#include "util.h"

class arpSocket
{
private:
    bool socketOpened;
    std::array<uint8_t, 6> sourceMac;
    uint32_t sourceIp;
    int socketFd;
    uint32_t ifindex;
    void fillArpRequestHeader(arpPacket* arp, const char* targetIp);
    void sendArpRequest(const char* targetIp);
    bool getArpReply(arpPacket* arp);
    std::string getMacAddressFromArpReply(const arpPacket* arp);

public:
    arpSocket();
    ~arpSocket();

    void createSocket(const char* interfaceName);
    void setTimeout(int sec, int usec);
    void closeSocket();
    void setSourceAddress(const char* sourceIp, const char* sourceMac);
    std::string getMacAddress(const char* targetIp, int retry = 3);
    
};

