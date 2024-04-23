#pragma once

#include "spoofAttack.h"
#include <utility>
#include <vector>


struct DNSquestionInfo
{
    std::array<uint8_t, 6> srcMAC, dstMAC;
    uint32_t srcIP, dstIP;
    uint16_t srcPort, dstPort;
    uint16_t DNSid;
    DNSFlags flags;
    bool hasSpecifiedURL;
    size_t specifiedURLoffset;
    size_t questionSectionSize;
};

class pharmAttack : public spoofAttack{
    private:
        bool checkIsDNS(const uint8_t* buffer, int bufferSize);
        DNSquestionInfo extractQuestionInfo(const uint8_t* buffer, int bufferSize);
        std::pair<uint8_t*, int> getDNSpacket(const uint8_t* buffer, int bufferSize);
        std::pair<uint8_t*, int> getDNSquestionSection(const uint8_t* DNSbuffer, int DNSsize);
        size_t checkIsDNSRequestToSpecificURL(const uint8_t* DNSbuffer, int DNSsize, const std::string& url);
        std::vector<uint8_t> generateDNSresponse(const uint8_t* DNSbuffer, int DNSsize, DNSquestionInfo info, uint32_t fakeIp);
        void encapsulate(std::vector<uint8_t> payload, DNSquestionInfo info);
    public:
        void processPackets(const char* interface) override;
};