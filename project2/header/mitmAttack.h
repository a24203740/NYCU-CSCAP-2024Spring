#pragma once

#include "spoofAttack.h"

class mitmAttack : public spoofAttack{
    private:
        bool checkIsHTTP(const uint8_t* buffer, int bufferSize);
        bool checkIsDNS(const uint8_t* buffer, int bufferSize);
        std::string getHTTPpayload(const uint8_t* buffer, int bufferSize);
        void extractHTTPpayload(std::string& payload);
    public:
        void processPackets(const char* interface) override;
};