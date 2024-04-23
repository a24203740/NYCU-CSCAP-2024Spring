#include "../header/ipSocket.h"

#include <net/if.h> // if_nametoindex
#include <unistd.h>
#include <iostream>

ipSocket::ipSocket()
{
    socketFd = -1;
    ifindex = 0;
    socketOpened = false;
}
ipSocket::~ipSocket()
{
    if(socketOpened) 
    {
        closeSocket();
    }
}

void ipSocket::modifyEthHeader(ethhdr* ethHeader, std::array<uint8_t, 6> destMac)
{
    std::copy(this->sourceMac.begin(), this->sourceMac.end(), ethHeader->h_source);
    std::copy(destMac.begin(), destMac.end(), ethHeader->h_dest);
}
bool ipSocket::checkNeedRedirect(const iphdr* ipHeader)
{
    return ipHeader->daddr != this->sourceIp;
}


void ipSocket::createSocket(const char* interfaceName) 
{
    if(socketOpened) {
        std::cerr << "[WARN] createSocket: has already opened socket, closing now..." << std::endl;
        closeSocket();
    }
    socketFd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    util::checkError(socketFd, "socket");
    socketOpened = true;
    sockaddr_ll sll{};
    sll.sll_family = AF_PACKET;
    util::checkError(this->ifindex = if_nametoindex(interfaceName), "if_nametoindex");
    // std::cerr << "[INFO] createSocket: interface " << interfaceName << " has ifindex " << this->ifindex << std::endl;
    sll.sll_ifindex = this->ifindex;
    util::checkError(bind(socketFd, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)), "bind");
}

void ipSocket::closeSocket() 
{
    if(socketOpened) {
        close(socketFd);
        socketOpened = false;
    }
}

void ipSocket::setSourceAddress(uint32_t sourceIp, std::array<uint8_t, 6> sourceMac) 
{
    this->sourceIp = sourceIp;
    this->sourceMac = sourceMac;
}

int ipSocket::receivePacketToMe(uint8_t* buffer, int bufferSize) 
{
    sockaddr_ll sll = sockaddr_ll{};
    socklen_t sllLen = sizeof(sockaddr_ll);
    int readBytes;
    while(true)
    {
        readBytes = recvfrom(socketFd, buffer, bufferSize, 0, reinterpret_cast<sockaddr*>(&sll), &sllLen);
        if(readBytes < 0) {
            util::checkError(readBytes, "recvfrom");
        }
        ethhdr* ethHeader = reinterpret_cast<ethhdr*>(buffer);
        if(ethHeader->h_proto != htons(ETH_P_IP)) {
            continue;
        }
        std::array<uint8_t, 6> destMac;
        std::copy(ethHeader->h_dest, ethHeader->h_dest + 6, destMac.data());
        if(destMac == this->sourceMac) {
            break;
        }
    }
    return readBytes;
}

void ipSocket::redirectPacket(void* packet, std::array<uint8_t, 6> destMac) 
{
    ethhdr* ethHeader = reinterpret_cast<ethhdr*>(packet);
    iphdr* ipHeader = reinterpret_cast<iphdr*>(reinterpret_cast<uint8_t*>(packet) + sizeof(ethhdr));    
    modifyEthHeader(ethHeader, destMac);
    size_t IPpacketSize = ntohs(ipHeader->tot_len);
    sockaddr_ll sll{}; 
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex = ifindex;
    sll.sll_halen = 6;
    std::copy(destMac.begin(), destMac.end(), sll.sll_addr);
    sendto(socketFd, packet, sizeof(ethhdr) + IPpacketSize, 0, reinterpret_cast<sockaddr*>(&sll), sizeof(sll));
}

void ipSocket::redirectPacket(void* packet, std::array<uint8_t, 6> destMac, uint32_t srcIp, uint32_t dstIp)
{
    iphdr* ipHeader = reinterpret_cast<iphdr*>(reinterpret_cast<uint8_t*>(packet) + sizeof(ethhdr));    
    ipHeader->saddr = srcIp;
    ipHeader->daddr = dstIp;
    redirectPacket(packet, destMac);
}

void ipSocket::sendPacket(void* packet, int packetSize, std::array<uint8_t, 6> destMac)
{
    sockaddr_ll sll{}; 
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex = ifindex;
    sll.sll_halen = 6;
    std::copy(destMac.begin(), destMac.end(), sll.sll_addr);
    sendto(socketFd, packet, packetSize, 0, reinterpret_cast<sockaddr*>(&sll), sizeof(sll));
}