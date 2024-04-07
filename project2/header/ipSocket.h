#pragma once

#include <string>
#include <array>
#include <cstdint>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#include "util.h"

class ipSocket
{
private:
    bool socketOpened;
    int socketFd;
    uint32_t sourceIp;
    std::array<uint8_t, 6> sourceMac;
    uint32_t ifindex;
    void modifyEthHeader(ethhdr* ethHeader, std::array<uint8_t, 6> destMac);
public:
    ipSocket();
    ~ipSocket();

    void createSocket(const char* interfaceName);
    void closeSocket();
    void setSourceAddress(uint32_t sourceIp, std::array<uint8_t, 6> sourceMac);
    int receivePacketToMe(uint8_t* buffer, int bufferSize);
    bool checkNeedRedirect(const iphdr* ipHeader);
    void redirectPacket(void* packet, std::array<uint8_t, 6> destMac);
};