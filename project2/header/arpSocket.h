#pragma once

#include <string>
#include <array>
#include <cctype>
#include <cstdint>
#include <linux/if_packet.h>

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
    void fillArpReplyHeader(arpPacket* arp, const arpPacket* request);
    void fillArpReplyHeader(arpPacket* arp, std::array<uint8_t, 6> targetMac, uint32_t targetIp, uint32_t fakeIp);
    bool getArpPacket(arpPacket* arp, sockaddr_ll* sll);
    bool checkIsReply(const arpPacket* arp);
    bool checkIsRequest(const arpPacket* arp);
    std::array<uint8_t, 6> getMacAddressFromArpReply(const arpPacket* arp);

public:
    arpSocket();
    ~arpSocket();

    void createSocket(const char* interfaceName);
    void setTimeout(int sec, int usec);
    void closeSocket();
    void setSourceAddress(uint32_t sourceIp, std::array<uint8_t, 6> sourceMac);
    void sendArpRequest(const char* targetIp);
    bool getArpReply(arpPacket* arp, bool waitUntilReceive = false);
    bool getArpRequest(arpPacket* arp, sockaddr_ll* sll, bool waitUntilReceive = true);
    void sendArpReply(const arpPacket* request, sockaddr_ll* sll);
    void sendArpReply(std::array<uint8_t, 6> targetMac, uint32_t targetIp, uint32_t fakeIp);
    std::array<uint8_t, 6> getMacAddress(const char* targetIp, int retry = 3);
    
};

