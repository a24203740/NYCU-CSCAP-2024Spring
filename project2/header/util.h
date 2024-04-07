#pragma once

#include <cstdint>
#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <array>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

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
    inline uint32_t stringToIp(std::string ip)
    {
        in_addr addr{};
        checkError(inet_pton(AF_INET, ip.c_str(), &addr), "inet_pton");
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
            res[i] = std::stoul(mac + 3*i, nullptr, 16);
        }
        return res;
    }

    inline std::array<uint8_t, 6> stringToMac(std::string mac)
    {
        int len = mac.size();
        std::array<uint8_t, 6> res{};
        if(len != 17)
        {
            errquit("Invalid MAC address");
        }
        for(int i = 0; i < 6; i++)
        {
            res[i] = std::stoul(mac.data() + 3*i, nullptr, 16);
        }
        return res;
    }

    inline uint32_t getDefaultGateway(const char* interface)
    {
        const char* routeFile = "/proc/net/route";
        std::ifstream file(routeFile);
        if(!file.is_open())
        {
            errquit("getDefaultGateway: failed to open /proc/net/route");
        }
        std::string line;
        std::getline(file, line); // skip first line
        std::string iface, destStr, gatewayStr;
        uint32_t dest, gateway;
        while(!file.eof())
        {
            file >> iface >> destStr >> gatewayStr;
            dest = std::stoul(destStr, nullptr, 16);
            gateway = std::stoul(gatewayStr, nullptr, 16);
            if(iface == interface && dest == 0)
            {
                return gateway;
            }
            std::getline(file, line); // skip rest of the line
        }
        return 0;
    }

    inline uint32_t getIPOfInterface(const char* interface)
    {
        int fd;
        struct ifreq ifr;
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        checkError(fd, "getIPofInterface: socket");
        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
        checkError(ioctl(fd, SIOCGIFADDR, &ifr), "getIPofInterface: ioctl");
        close(fd);

        in_addr_t ip = reinterpret_cast<sockaddr_in*>(&ifr.ifr_addr)->sin_addr.s_addr;
        return ip;
    }

    inline std::array<uint8_t, 6> getMacOfInterface(const char* interface)
    {
        int fd;
        struct ifreq ifr;
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        checkError(fd, "getMacOfInterface: socket");
        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
        checkError(ioctl(fd, SIOCGIFHWADDR, &ifr), "getMacOfInterface: ioctl");
        close(fd);

        std::array<uint8_t, 6> mac;
        std::copy(ifr.ifr_hwaddr.sa_data, ifr.ifr_hwaddr.sa_data + 6, mac.data());
        return mac;
    }

}
