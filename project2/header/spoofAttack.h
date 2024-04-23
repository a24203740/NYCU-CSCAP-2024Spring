#pragma once

#include <map>
#include <string>
#include <array>
#include <stdint.h>

#include "arpSocket.h"
#include "ipSocket.h"
#include "util.h"

class spoofAttack {
    protected:
        arpSocket arp;
        ipSocket ip;

        uint32_t myIp;
        std::array<uint8_t, 6> myMac;
        std::map<in_addr_t, std::array<uint8_t, 6>> IPToMac;

    public:
        void setupSocket(const char* interface);
        void getNeighbours(uint32_t gatewayIP);
        void poisonNeighbours();
        virtual void processPackets(const char* interface) = 0;
};