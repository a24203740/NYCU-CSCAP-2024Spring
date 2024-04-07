#include "../header/arpSocket.h"

#include <unistd.h>
#include <cstring>
#include <iostream>

#include <sys/socket.h>
#include <net/if.h> // if_nametoindex
#include <arpa/inet.h>
#include <netinet/if_ether.h>

arpSocket::arpSocket() {
    socketFd = -1;
    ifindex = 0;
    socketOpened = false;
}

arpSocket::~arpSocket() {
    if(socketOpened) {
        closeSocket();
    }
}

void arpSocket::fillArpRequestHeader(arpPacket* arp, const char* targetIp) {
    arp->hardwareType = htons(1);
    arp->protocolType = htons(ETH_P_IP);
    arp->hardwareSize = 6;
    arp->protocolSize = 4;
    arp->operation = htons(1); // arp request
    // std::cerr << "[INFO] fillArpRequestHeader: sourceMac " << util::macToString(sourceMac.data()) << std::endl;
    std::copy(sourceMac.begin(), sourceMac.end(), arp->senderMac);
    arp->senderIp = sourceIp;
    std::fill(arp->targetMac, arp->targetMac + 6, 0);
    arp->targetIp = util::stringToIp(targetIp);
}

void arpSocket::fillArpReplyHeader(arpPacket* arp, const arpPacket* request)
{
    arp->hardwareType = htons(1);
    arp->protocolType = htons(ETH_P_IP);
    arp->hardwareSize = 6;
    arp->protocolSize = 4;
    arp->operation = htons(2); // arp reply
    std::copy(this->sourceMac.begin(), this->sourceMac.end(), arp->senderMac); //fake mac
    arp->senderIp = request->targetIp; 
    std::copy(request->senderMac, request->senderMac + 6, arp->targetMac);
    arp->targetIp = request->senderIp;
}

void arpSocket::fillArpReplyHeader(arpPacket* arp, std::array<uint8_t, 6> targetMac, uint32_t targetIp, uint32_t fakeIp)
{
    arp->hardwareType = htons(1);
    arp->protocolType = htons(ETH_P_IP);
    arp->hardwareSize = 6;
    arp->protocolSize = 4;
    arp->operation = htons(2); // arp reply
    std::copy(this->sourceMac.begin(), this->sourceMac.end(), arp->senderMac); //fake mac
    arp->senderIp = fakeIp; 
    std::copy(targetMac.begin(), targetMac.end(), arp->targetMac);
    arp->targetIp = targetIp;
}

bool arpSocket::getArpPacket(arpPacket* arp, sockaddr_ll* sll)
{
    if(!socketOpened) {
        util::errquit("getArpReply: socket not exist");
    }
    while(true)
    {
        *sll = sockaddr_ll{};
        socklen_t sllLen = sizeof(sockaddr_ll);
        int readBytes = recvfrom(socketFd, arp, sizeof(arpPacket), 0, reinterpret_cast<sockaddr*>(sll), &sllLen);
        if(readBytes < 0) {
            if(errno == EAGAIN || errno == EWOULDBLOCK) {
                return false;
            }
            util::checkError(readBytes, "recvfrom");
        }
        if(readBytes != sizeof(arpPacket)) {
            // std::cerr << "[WARN] getArpReply: received packet size is not arp packet size, continue..." << std::endl;
            continue;
        }
        break;
    }
    return true;
}
bool arpSocket::checkIsReply(const arpPacket* arp)
{
    return (arp->hardwareType == htons(1) && arp->protocolType == htons(ETH_P_IP) && arp->operation == htons(2));
}
bool arpSocket::checkIsRequest(const arpPacket* arp)
{
    return (arp->hardwareType == htons(1) && arp->protocolType == htons(ETH_P_IP) && arp->operation == htons(1));
}

void arpSocket::sendArpRequest(const char* targetIp) {
    if(!socketOpened) {
        util::errquit("sendArpRequest: socket not exist");
    }
    arpPacket arp{};
    fillArpRequestHeader(&arp, targetIp);
    sockaddr_ll sll{}; // tell kernel how to encapsulate the packet ethernet header
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ARP);
    sll.sll_ifindex = ifindex;
    sll.sll_hatype = htons(ARPHRD_ETHER);
    sll.sll_halen = 6;
    sll.sll_pkttype = PACKET_BROADCAST;
    std::fill(sll.sll_addr, sll.sll_addr + 6, 0xff);
    int sendBytes = sendto(socketFd, &arp, sizeof(arpPacket), 0, reinterpret_cast<sockaddr*>(&sll), sizeof(sockaddr_ll));
    // std::cerr << "[INFO] sendArpRequest: send " << sendBytes << " bytes" << std::endl;
    util::checkError(sendBytes, "sendto");
}

void arpSocket::sendArpReply(const arpPacket* request, sockaddr_ll *sll) {
    if(!socketOpened) {
        util::errquit("sendArpReply: socket not exist");
    }
    arpPacket arp{};
    fillArpReplyHeader(&arp, request);
    int sendBytes = sendto(socketFd, &arp, sizeof(arpPacket), 0, reinterpret_cast<sockaddr*>(sll), sizeof(sockaddr_ll));
    // std::cerr << "[INFO] sendArpReply: send " << sendBytes << " bytes" << std::endl;
    util::checkError(sendBytes, "sendto");
}

void arpSocket::sendArpReply(std::array<uint8_t, 6> targetMac, uint32_t targetIp, uint32_t fakeIp) {
    if(!socketOpened) {
        util::errquit("sendArpReply: socket not exist");
    }
    arpPacket arp{};
    fillArpReplyHeader(&arp, targetMac, targetIp, fakeIp);
    sockaddr_ll sll{}; // tell kernel how to encapsulate the packet ethernet header
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ARP);
    sll.sll_ifindex = ifindex;
    sll.sll_halen = 6;
    std::copy(targetMac.begin(), targetMac.end(), sll.sll_addr);
    int sendBytes = sendto(socketFd, &arp, sizeof(arpPacket), 0, reinterpret_cast<sockaddr*>(&sll), sizeof(sockaddr_ll));
    // std::cerr << "[INFO] sendArpReply: send " << sendBytes << " bytes" << std::endl;
    util::checkError(sendBytes, "sendto");
}

bool arpSocket::getArpReply(arpPacket* arp, bool waitUntilReceive) {
    while(true)
    {
        sockaddr_ll sll{};
        if(getArpPacket(arp, &sll)) {
            if(!checkIsReply(arp)) {
                continue;
            }
            std::array<uint8_t, 6> targetMac{};
            std::copy(arp->targetMac, arp->targetMac + 6, targetMac.data());
            if(targetMac != sourceMac) {
                continue;
            }
            // got arp reply for us
            return true;
        }
        else if(!waitUntilReceive) {
            return false;
        }
        else {
            continue;
        }
    }
    // got arp reply for us
    return true;
}

bool arpSocket::getArpRequest(arpPacket* arp, sockaddr_ll* sll, bool waitUntilReceive) {
    while(true)
    {
        if(getArpPacket(arp, sll)) {
            if(!checkIsRequest(arp)) {
                continue;
            }
            // we want receive every arp request
            return true;
        }
        else if(!waitUntilReceive) {
            return false;
        }
        else {
            continue;
        }
    }
    return true;
}



std::array<uint8_t, 6> arpSocket::getMacAddressFromArpReply(const arpPacket* arp) {
    std::array<uint8_t, 6> targetMac;
    std::copy(arp->senderMac, arp->senderMac + 6, targetMac.data());
    return targetMac;
}


void arpSocket::createSocket(const char* interfaceName) {
    if(socketOpened) {
        std::cerr << "[WARN] createSocket: has already opened socket, closing now..." << std::endl;
        closeSocket();
    }
    socketFd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
    util::checkError(socketFd, "socket");
    socketOpened = true;
    sockaddr_ll sll{};
    sll.sll_family = AF_PACKET;
    util::checkError(this->ifindex = if_nametoindex(interfaceName), "if_nametoindex");
    // std::cerr << "[INFO] createSocket: interface " << interfaceName << " has ifindex " << this->ifindex << std::endl;
    sll.sll_ifindex = this->ifindex;
    util::checkError(bind(socketFd, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)), "bind");
}

void arpSocket::setTimeout(int sec, int usec) {
    if(!socketOpened) {
        util::errquit("setTimeout: socket not exist");
    }
    struct timeval timeout;
    timeout.tv_sec = sec;
    timeout.tv_usec = usec;
    util::checkError(setsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)), "setsockopt");   
}

void arpSocket::closeSocket() {
    if(!socketOpened) {
        return;
    }
    util::checkError(close(socketFd), "close");
    socketOpened = false;
}

void arpSocket::setSourceAddress(uint32_t sourceIp, std::array<uint8_t, 6> sourceMac) {
    this->sourceIp = sourceIp;
    this->sourceMac = sourceMac;
}

std::array<uint8_t, 6> arpSocket::getMacAddress(const char* targetIp, int retry) {
    if(!socketOpened) {
        util::errquit("getMacAddress: socket not exist");
    }
    bool success = false;
    int count = 0;
    arpPacket returnArp;
    while(!success && count < retry) {
        sendArpRequest(targetIp);
        returnArp = arpPacket{};
        success = getArpReply(&returnArp);
        if(!success) {
            count++;
            // std::cerr << "[WARN] getMacAddress: fail on " << targetIp << " for "  << count << " times" << std::endl;
        }
    }
    if(!success) {
        return std::array<uint8_t, 6>{};
    }
    return getMacAddressFromArpReply(&returnArp);
}
