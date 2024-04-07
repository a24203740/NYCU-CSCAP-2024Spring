#pragma once

#include <map>
#include <string>
#include <array>
#include <stdint.h>

#include "arpSocket.h"
#include "ipSocket.h"
#include "util.h"

class mitmAttack {
    private:
        arpSocket arp;
        ipSocket ip;

        uint32_t myIp;
        std::array<uint8_t, 6> myMac;
        std::map<in_addr_t, std::array<uint8_t, 6>> IPToMac;

        bool checkIsHTTP(const uint8_t* buffer, int bufferSize);
        bool checkIsDNS(const uint8_t* buffer, int bufferSize);
        std::string getHTTPpayload(const uint8_t* buffer, int bufferSize);
        void extractHTTPpayload(std::string& payload);
    public:
        void setupSocket(const char* interface);
        void getNeighbours();
        void poisonNeighbours();
        void processPackets(const char* interface);
};