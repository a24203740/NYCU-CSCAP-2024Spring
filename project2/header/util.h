#pragma once

#include <cstdint>
#include <iostream>
#include <string>
#include <cstring>
#include <array>
#include <arpa/inet.h>

struct arpPacket
{
    uint16_t hardwareType;
    uint16_t protocolType;
    uint8_t hardwareSize;
    uint8_t protocolSize;
    uint16_t operation;
    uint8_t senderMac[6];
    uint32_t senderIp;
    uint8_t targetMac[6];
    uint32_t targetIp;
} __attribute__((packed));

namespace util{

    inline void checkError(int res, const char* msg)
    {
        if(res < 0)
        {
            perror(msg);
            exit(1);
        }
    }

    inline void errquit(const char* msg)
    {
        std::cerr << "[ERROR] " << msg << std::endl;
        exit(1);
    }

    inline std::string ipToString(uint32_t ip)
    {
        char buffer[64];
        in_addr addr{};
        addr.s_addr = ip;
        auto res = inet_ntop(AF_INET, &addr, buffer, sizeof(buffer));
        if(res == nullptr)
        {
            checkError(-1, "inet_ntop"); // get errno
        }
        return std::string(buffer);
    }

    inline uint32_t stringToIp(const char* ip)
    {
        in_addr addr{};
        checkError(inet_pton(AF_INET, ip, &addr), "inet_pton");
        return addr.s_addr;
    }

    inline std::string macToString(const uint8_t* mac)
    {
        char buffer[64];
        sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return std::string(buffer);
    }

    inline std::array<uint8_t, 6> stringToMac(const char* mac)
    {
        int len = strlen(mac);
        std::array<uint8_t, 6> res{};
        if(len != 17)
        {
            errquit("Invalid MAC address");
        }
        for(int i = 0; i < 6; i++)
        {
            std::string subStr(mac + 3*i, 2);
            res[i] = std::stoul(mac + 3*i, nullptr, 16);
        }
        return res;
    }


}
