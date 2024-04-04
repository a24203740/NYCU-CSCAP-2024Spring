#include "session.h"

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <span>
#include <utility>

extern bool running;

/*

*   what we want to get from server?
*       tcpseq => use to fill out tcpAckSeq (+1 or +0)
*       tcpackseq => use to fill out tcpSeq (+0)
*       tcpdstPort => use to fill out tcpSourcePort
*       tcpsrcPort => use to fill out tcpDstport
*       secret => if any

*   what we want to get from client?
*       ipId => use to fill out ipId (+1)
*       ESPseq => use to fill out ESPseq (+1)

*/
struct pseudo_header 
{
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_length;
};

uint16_t calculateChecksum(uint16_t *ptr, int nbytes, uint32_t init) {
    uint32_t sum = init;
    uint16_t answer = 0;
    uint16_t *w = ptr;
    int nleft = nbytes;

    // Sum up 16-bit words
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    // Add left-over byte, if any
    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    // Fold 32-bit sum to 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

uint16_t caculateTCPchecksum(uint16_t *ptr, uint32_t src, uint32_t dst, uint16_t tcpSize)
{
    uint32_t sum = 0;
    uint16_t answer = 0;

    pseudo_header ph{};
    ph.source_address = src;
    ph.dest_address = dst;
    ph.protocol = 6; 
    ph.tcp_length = htons(tcpSize);
    uint16_t* ptrPh = reinterpret_cast<uint16_t*>(&ph);

    for(int i = 0; i < 12; i+=2)
    {
        sum += *ptrPh;
        ptrPh++;
    }

    answer = calculateChecksum(ptr, tcpSize, sum);
    return answer;

}


Session::Session(const std::string& iface, ESPConfig&& cfg)
    : sock{0}, recvBuffer{}, sendBuffer{}, config{std::move(cfg)}, state{} {
    checkError(sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL)), "Create socket failed");
    // TODO: Setup sockaddr_ll
    sockaddr_ll addr_ll{};
    addr_ll.sll_family = htons(AF_PACKET);
    addr_ll.sll_protocol = htons(ETH_P_ALL);
    unsigned int ifindex;
    checkError(ifindex = if_nametoindex(iface.c_str()), "get if index");
    addr_ll.sll_ifindex = htonl(ifindex);
    checkError(bind(sock, reinterpret_cast<sockaddr*>(&addr_ll), sizeof(sockaddr_ll)), "Bind failed");
}

Session::~Session() {
    shutdown(sock, SHUT_RDWR);
    close(sock);
}

void Session::run() {
    epoll_event triggeredEvent[2];
    epoll_event event;
    Epoll ep;

    event.events = EPOLLIN;
    event.data.fd = 0;
    checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, 0, &event), "Failed to add stdin to epoll");
    event.data.fd = sock;
    checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, sock, &event), "Failed to add sock to epoll");

    std::string secret;
    std::cout << "You can start to send the message...\n";
    while (running) {
        int cnt = epoll_wait(ep.fd, triggeredEvent, 2, 500);
        for (int i = 0; i < cnt; i++) {
            if (triggeredEvent[i].data.fd == 0) {
                std::getline(std::cin, secret);
            } else {
                ssize_t readCount = recvfrom(sock, recvBuffer, sizeof(recvBuffer), 0,
                                            reinterpret_cast<sockaddr*>(&addr), &addrLen);
                checkError(readCount, "Failed to read sock");
                state.sendAck = false;
                dissect(readCount);
                if (state.sendAck) 
                {
                    encapsulate("");
                    // encapsulate("ThisSequenceIsSoLongThanYouYouStupidClientHahahahahahahahhahahahahaha\n");
                }
                if (!secret.empty() && state.recvPacket) {
                    encapsulate(secret);
                    secret.clear();
                }
                
            }
        }
    }
}

void Session::dissect(ssize_t rdcnt) {
    auto payload = std::span{recvBuffer, recvBuffer + rdcnt};
    // TODO: NOTE
    // In following packet dissection code, we should set parameters if we are
    // receiving packets from remote
    dissectIPv4(payload);
}

void Session::dissectIPv4(std::span<uint8_t> buffer) {
    // std::cerr << "Dissect IPv4" << std::endl;
    auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
    unsigned int headerSize = hdr.ihl * 4;
    in_addr_t sourceAddr = hdr.saddr; // it is using pton/ntop in util, we do not need hton/ntoh here

    // TODO:
    // * Set recvPacket = true if we are receiving packet from remote
    if(stringToIPv4(config.remote).s_addr == sourceAddr)
    {
        // std::cerr << "packet from server" << std::endl;
        state.recvPacket = true;
    }
    else
    {
        // std::cerr << "packet from client" << std::endl;
        state.recvPacket = false;
        state.sendAck = false;
    }

    // std::cerr << "from " << ipToString(sourceAddr) << " to " << ipToString(hdr.daddr) << std::endl;
    if(state.recvPacket == false)
    {
        // * Track current IP id
        state.ipId = ntohs(hdr.id);
        // std::cerr << "last ipId of client: " << state.ipId << std::endl;
    }

    // std::cerr << "ip version " << (int)hdr.version << std::endl;
    // std::cerr << "ip ihl " << (int)hdr.ihl << std::endl;
    // std::cerr << "ip tos " << (int)hdr.tos << std::endl;
    // std::cerr << "ip id " << ntohs(hdr.id) << std::endl;
    // std::cerr << "ip ttl " << (int)hdr.ttl << std::endl;
    // std::cerr << "ip total fragoff field " << ntohs(hdr.frag_off) << std::endl;
    // std::cerr << "ip flag " << ((ntohs(hdr.frag_off)) >> 13) << std::endl;
    // std::cerr << "ip frag_off " << (ntohs(hdr.frag_off) & ((1<<13)-1)) << std::endl;
    
    // * Call dissectESP(payload) if next protocol is ESP
    if(hdr.protocol == IPPROTO_ESP) // defined in in.h
    {
        auto payload = buffer.last(buffer.size() - headerSize);
        dissectESP(payload);
    }
}

void Session::dissectESP(std::span<uint8_t> buffer) {
    // std::cerr << "Dissect ESP" << std::endl;
    auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
    int hashLength = config.aalg->hashLength();
    // Strip hash
    // buffer will be IPv4 payload alongwith ESP trailer(padding), without ESP auth data

    buffer = buffer.subspan(sizeof(ESPHeader), buffer.size() - sizeof(ESPHeader) - hashLength);
    std::vector<uint8_t> data;
    // Decrypt payload
    if (!config.ealg->empty()) {
        data = config.ealg->decrypt(buffer);
        buffer = std::span{data.data(), data.size()};
    }
    uint8_t paddingLength;
    uint8_t nextHeader;
    if(buffer.size() >= 2)
    {
        paddingLength = buffer[buffer.size() - 2];
    }
    if(!buffer.empty())
    {
        nextHeader = buffer.back();
    }
    // TODO:
    if(state.recvPacket == false)
    {
        // * Track ESP sequence number
        if(state.espseq < ntohl(hdr.seq))
        {
            state.espseq = ntohl(hdr.seq);
        }
        config.spi = ntohl(hdr.spi); // sadb dump spi is from server...
        // std::cerr << "client ESP seq: " << state.espseq << std::endl;
    }
    // * Call dissectTCP(payload) if next protocol is TCP
    if(nextHeader == IPPROTO_TCP)
    {
        auto payload = buffer.first(buffer.size() - paddingLength - 2);
        dissectTCP(payload);
    }
}

void Session::dissectTCP(std::span<uint8_t> buffer) {
    // std::cerr << "Dissect TCP" << std::endl;
    auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
    auto length = hdr.doff << 2;
    auto payload = buffer.last(buffer.size() - length);
    // * Track tcp parameters
    if(state.recvPacket)
    {
        state.tcpseq = ntohl(hdr.ack_seq);
        state.tcpackseq = ntohl(hdr.seq);
        state.srcPort = ntohs(hdr.source);
        state.dstPort = ntohs(hdr.dest);
        // std::cerr << "server TCP tcpseq is: " << state.tcpseq << std::endl;
        // std::cerr << "server TCP tcpackseq is: " << state.tcpackseq << std::endl;
        // std::cerr << "server TCP srcPort is: " << state.srcPort << std::endl;
        // std::cerr << "server TCP dstPort is: " << state.dstPort << std::endl;
    }

    // std::cerr << "TCP cksum: " << htons(hdr.check) << std::endl;
    // hdr.check = 0;
    // uint16_t myCksum;
    // in_addr_t srcAddr = stringToIPv4(config.local).s_addr;
    // in_addr_t dstAddr = stringToIPv4(config.remote).s_addr;
    // uint16_t* ptr = reinterpret_cast<uint16_t*>(buffer.data());
    // if(state.recvPacket)
    // {
    //     myCksum = caculateTCPchecksum(ptr, dstAddr, srcAddr, buffer.size());
    // }
    // else
    // {
    //     myCksum = caculateTCPchecksum(ptr, srcAddr, dstAddr, buffer.size());
    // }
    // std::cerr << "My Cksum: " << htons(myCksum) << std::endl;

    if (state.recvPacket) {
        if (payload.empty())
        {
            // std::cerr << "ACK occured from server" << std::endl;
            state.sendAck = false;
            return;
        } 
        // We only got non ACK when we receive secret, then we need to send ACK
        std::cout << "Secret: " << std::string(payload.begin(), payload.end()) << std::endl;
        state.tcpackseq += payload.size();
        state.sendAck = true;
    }
}

void Session::encapsulate(const std::string& payload) {
    auto buffer = std::span{sendBuffer};
    std::fill(buffer.begin(), buffer.end(), 0);
    int totalLength = encapsulateIPv4(buffer, payload);
    sendto(sock, sendBuffer, totalLength, 0, reinterpret_cast<sockaddr*>(&addr), addrLen);
}

int Session::encapsulateIPv4(std::span<uint8_t> buffer, const std::string& payload) {
    auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
    // TODO: Fill IP header
    hdr.version = 4;
    hdr.ihl = 5; // no options
    hdr.ttl = 64; // I guess every number is good
    hdr.id = htons(state.ipId + 1); // add 1 to last client IPid
    hdr.protocol = IPPROTO_ESP; // payload protocol
    hdr.frag_off = htons((2<<13) + 0); // 2 = Don't Fragment
    hdr.saddr = stringToIPv4(config.local).s_addr;
    hdr.daddr = stringToIPv4(config.remote).s_addr;

    auto nextBuffer = buffer.last(buffer.size() - sizeof(iphdr));
    int payloadLength = encapsulateESP(nextBuffer, payload);

    payloadLength += sizeof(iphdr);
    hdr.tot_len = htons(payloadLength);
    // * caculate checksum
    hdr.check = 0;
    uint16_t* twoBytesPtr = reinterpret_cast<uint16_t*>(buffer.data());
    uint16_t checksum = calculateChecksum(twoBytesPtr, 20, 0);
    hdr.check = checksum;
    return payloadLength;
}

int Session::encapsulateESP(std::span<uint8_t> buffer, const std::string& payload) {
    auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
    auto nextBuffer = buffer.last(buffer.size() - sizeof(ESPHeader));
    // TODO: Fill ESP header
    hdr.spi = htonl(config.spi); 
    hdr.seq = htonl(state.espseq+1); // client espSeq + 1
    state.espseq++;
    int payloadLength = encapsulateTCP(nextBuffer, payload);

    auto endBuffer = nextBuffer.last(nextBuffer.size() - payloadLength);
    // TODO: Calculate padding size and do padding in `endBuffer`
    uint8_t padSize = 4 - ((payloadLength + 2) % 4);// align with pad length and next header
    payloadLength += padSize;
    // ESP trailer
    endBuffer[padSize] = padSize;
    endBuffer[padSize + 1] = IPPROTO_TCP;
    payloadLength += sizeof(ESPTrailer);
    // Do encryption
    if (!config.ealg->empty()) {
        auto result = config.ealg->encrypt(nextBuffer.first(payloadLength));
        std::copy(result.begin(), result.end(), nextBuffer.begin());
        payloadLength = result.size();
    }
    payloadLength += sizeof(ESPHeader);

    if (!config.aalg->empty()) {
        // TODO: Fill in config.aalg->hash()'s parameter
        auto result = config.aalg->hash(buffer.first(payloadLength));
        std::copy(result.begin(), result.end(), buffer.begin() + payloadLength);
        payloadLength += result.size();
    }
    return payloadLength;
}

int Session::encapsulateTCP(std::span<uint8_t> buffer, const std::string& payload) {
    auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
    if (!payload.empty()) hdr.psh = 1;
    // TODO: Fill TCP header
    hdr.ack = 1;
    hdr.doff = (20 >> 2);
    hdr.dest = htons(state.srcPort);
    hdr.source = htons(state.dstPort);
    hdr.ack_seq = htonl(state.tcpackseq);
    hdr.seq = htonl(state.tcpseq);
    hdr.window = htons(502); // some random number I guess.
    auto nextBuffer = buffer.last(buffer.size() - sizeof(tcphdr));
    int payloadLength = 0;
    if (!payload.empty()) {
        // std::cerr << "sending \"" << payload << "\"" << std::endl; 
        std::copy(payload.begin(), payload.end(), nextBuffer.begin());
        payloadLength += payload.size();
    }
    // TODO: Update TCP sequence number
    state.tcpseq = state.tcpseq + payloadLength;
    payloadLength += sizeof(tcphdr);
    // TODO: Compute checksum
    hdr.check = 0;
    uint16_t myCksum;
    in_addr_t srcAddr = stringToIPv4(config.local).s_addr;
    in_addr_t dstAddr = stringToIPv4(config.remote).s_addr;
    uint16_t* ptr = reinterpret_cast<uint16_t*>(buffer.data());
    
    myCksum = caculateTCPchecksum(ptr, srcAddr, dstAddr, payloadLength);
    hdr.check = myCksum;
    // std::cerr << "checksum TCP = " << myCksum << std::endl;
    return payloadLength;
}
