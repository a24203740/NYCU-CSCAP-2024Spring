#include "../header/arpSocket.h"

#include <unistd.h>
#include <cstring>
#include <iostream>

#include <sys/socket.h>
#include <net/if.h> // if_nametoindex
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>

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
    std::cerr << "[INFO] fillArpRequestHeader: sourceMac " << util::macToString(sourceMac.data()) << std::endl;
    std::copy(sourceMac.begin(), sourceMac.end(), arp->senderMac);
    arp->senderIp = sourceIp;
    std::fill(arp->targetMac, arp->targetMac + 6, 0);
    arp->targetIp = util::stringToIp(targetIp);
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
    int sendBytes = sendto(socketFd, &arp, sizeof(arpPacket), 0, reinterpret_cast<sockaddr*>(&sll), sizeof(sll));
    std::cerr << "[INFO] sendArpRequest: send " << sendBytes << " bytes" << std::endl;
    util::checkError(sendBytes, "sendto");
}

bool arpSocket::getArpReply(arpPacket* arp) {
    if(!socketOpened) {
        util::errquit("getArpReply: socket not exist");
    }
    while(true)
    {
        sockaddr_ll sll{};
        socklen_t sllLen = sizeof(sll);
        int readBytes = recvfrom(socketFd, arp, sizeof(arpPacket), 0, reinterpret_cast<sockaddr*>(&sll), &sllLen);
        if(readBytes < 0) {
            if(errno == EAGAIN || errno == EWOULDBLOCK) {
                return false;
            }
            util::checkError(readBytes, "recvfrom");
        }
        if(readBytes != sizeof(arpPacket)) {
            std::cerr << "[WARN] getArpReply: received packet size is not arp packet size, continue..." << std::endl;
            continue;
        }
        // check if this arp reply is arp reply
        if(arp->hardwareType != htons(1) || arp->protocolType != htons(ETH_P_IP) || arp->operation != htons(2)) {
            // operation 2 is arp reply
            continue;
        }
        // check if this arp reply is for me
        std::array<uint8_t, 6> arpMac{};
        std::copy(arp->targetMac, arp->targetMac + 6, arpMac.begin());
        if(arpMac != sourceMac) {
            continue;
        }
        break;
    }
    // got arp reply for us
    return true;
}

std::string arpSocket::getMacAddressFromArpReply(const arpPacket* arp) {
    uint8_t targetMac[6];
    std::copy(arp->senderMac, arp->senderMac + 6, targetMac);
    return util::macToString(targetMac);
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
    std::cerr << "[INFO] createSocket: interface " << interfaceName << " has ifindex " << this->ifindex << std::endl;
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

void arpSocket::setSourceAddress(const char* sourceIp, const char* sourceMac) {
    this->sourceIp = util::stringToIp(sourceIp);
    this->sourceMac = util::stringToMac(sourceMac);
}

std::string arpSocket::getMacAddress(const char* targetIp, int retry) {
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
            std::cerr << "[WARN] getMacAddress: fail on " << targetIp << " for "  << count << " times" << std::endl;
        }
    }
    if(!success) {
        return "";
    }
    return getMacAddressFromArpReply(&returnArp);
}
