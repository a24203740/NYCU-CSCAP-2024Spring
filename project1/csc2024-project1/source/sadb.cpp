#include "sadb.h"

#include <arpa/inet.h>
#include <unistd.h> // getpid
#include <cstring>

#include <iomanip>
#include <iostream>

std::optional<ESPConfig> getConfigFromSADB() {
    // Allocate buffer
    std::vector<uint8_t> message(65536);
    sadb_msg msg{};
    // TODO: Fill sadb_msg
    msg.sadb_msg_version = PF_KEY_V2;
    msg.sadb_msg_type = SADB_DUMP;
    msg.sadb_msg_satype = SADB_SATYPE_ESP;
    msg.sadb_msg_seq = 0;
    msg.sadb_msg_len = sizeof(sadb_msg) / 8; // in 8 bytes unit. EMSGSIZE when mismatch.
    msg.sadb_msg_pid = getpid();
    std::cerr << "setup message" << std::endl;

    // TODO: Create a PF_KEY_V2 socket and write msg to it
    int s;
    s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    checkError(s, "socket");

    ssize_t res;
    checkError(write(s, &msg, sizeof(sadb_msg)), "write");
    // TODO: Set size to number of bytes in response message
    sadb_msg responseHeader{};
    // * after sending a SADB_DUMP msg, we receive some SADB_DUMP msg
    // ? maybe we should check if the return msg is for SA_DUMP first?
    res = read(s, message.data(), message.size());
    checkError(res, "read msg");
    std::memcpy(&responseHeader, message.data(), sizeof(sadb_msg));
    size_t totalSize = responseHeader.sadb_msg_len * 8;
    if(res != totalSize)
    {
        std::cerr << "WARNING: read size mismatched with reponsed size" << std::endl;
    }

    // Has SADB entry
    // return: <base, SA, (lifetime (HSC),) address(SD), (address(P),)
    // key(AE), (identity(SD),) (sensitivity)>
    if (totalSize != sizeof(sadb_msg)) {
        // * retreive sadb_key from message (RFC 2367 2.3.4)
        ESPConfig config{};
        // TODO: Parse SADB message
        sadb_ext extHeader{};
        uint32_t spi;
        int authAlgId;
        int encryptAlgId;
        bool hasEncryptAlgo = false;
        std::span<uint8_t> authKey{};
        std::span<uint8_t> encryptKey{};
        uint32_t srcAddr;
        uint32_t dstAddr;

        int index = sizeof(sadb_msg);
        while(index < totalSize)
        {
            sadb_sa sa{};
            sadb_key key{};
            // sadb_address addr{};
            size_t keyLengthInBytes;
            size_t keyStartByte;
            size_t keyEndByte;
            sockaddr_in srcSockAddrIn{}, dstSockAddrIn{};

            std::memcpy(&extHeader, message.data() + index, sizeof(extHeader));
            std::cerr << std::endl << "size is " << (int)extHeader.sadb_ext_len*8 << " type is " << (int)extHeader.sadb_ext_type << std::endl;
            switch (extHeader.sadb_ext_type)
            {
                case SADB_EXT_SA:
                    std::cerr << "SADB type is: SADB_EXT_SA" << std::endl;
                    
                    std::memcpy(&sa, message.data() + index, sizeof(sadb_sa));
                    spi = sa.sadb_sa_spi;
                    authAlgId = sa.sadb_sa_auth;
                    encryptAlgId = sa.sadb_sa_encrypt;
                    break;
                case SADB_EXT_LIFETIME_CURRENT:
                    std::cerr << "SADB type is: SADB_EXT_LIFETIME_CURRENT" << std::endl;
                    break;
                case SADB_EXT_LIFETIME_HARD:
                    std::cerr << "SADB type is: SADB_EXT_LIFETIME_HARD" << std::endl;
                    break;
                case SADB_EXT_LIFETIME_SOFT:
                    std::cerr << "SADB type is: SADB_EXT_LIFETIME_SOFT" << std::endl;
                    break;
                case SADB_EXT_ADDRESS_SRC:
                    std::memcpy(&srcSockAddrIn, message.data() + index + sizeof(sadb_address), sizeof(sockaddr_in));
                    srcAddr = srcSockAddrIn.sin_addr.s_addr;
                    std::cerr << "SADB type is: SADB_EXT_ADDRESS_SRC" << std::endl;
                    break;
                case SADB_EXT_ADDRESS_DST:
                    std::memcpy(&dstSockAddrIn, message.data() + index + sizeof(sadb_address), sizeof(sockaddr_in));
                    dstAddr = dstSockAddrIn.sin_addr.s_addr;
                    std::cerr << "SADB type is: SADB_EXT_ADDRESS_DST" << std::endl;
                    break;
                case SADB_EXT_ADDRESS_PROXY:
                    std::cerr << "SADB type is: SADB_EXT_ADDRESS_PROXY" << std::endl;
                    break;
                case SADB_EXT_KEY_AUTH:
                    
                    std::memcpy(&key, message.data() + index, sizeof(sadb_key));
                    keyLengthInBytes = key.sadb_key_bits / 8;
                    if(key.sadb_key_bits % 8 != 0)keyLengthInBytes++;
                    keyStartByte = index + sizeof(sadb_key);
                    keyEndByte = keyStartByte + keyLengthInBytes;
                    authKey = std::span(message.begin() + keyStartByte, message.begin() + keyEndByte);
                    std::cerr << "SADB type is: SADB_EXT_KEY_AUTH" << std::endl;
                    std::cerr << "key bits long: " << key.sadb_key_bits << std::endl;
                    std::cerr << "key bytes long (may with padding)" << keyLengthInBytes << std::endl;
                    break;
                case SADB_EXT_KEY_ENCRYPT:
                    hasEncryptAlgo = true;
                    std::memcpy(&key, message.data() + index, sizeof(sadb_key));
                    keyLengthInBytes = key.sadb_key_bits / 8;
                    if(key.sadb_key_bits % 8 != 0)keyLengthInBytes++;
                    keyStartByte = index + sizeof(sadb_key);
                    keyEndByte = keyStartByte + keyLengthInBytes;
                    encryptKey = std::span(message.begin() + keyStartByte, message.begin() + keyEndByte);
                    std::cerr << "SADB type is: SADB_EXT_KEY_ENCRYPT" << std::endl;
                    std::cerr << "key bits long: " << key.sadb_key_bits << std::endl;
                    std::cerr << "key bytes long (may with padding)" << keyLengthInBytes << std::endl;
                    break;
                case SADB_EXT_IDENTITY_SRC:
                    std::cerr << "SADB type is: SADB_EXT_IDENTITY_SRC" << std::endl;
                    break;
                case SADB_EXT_IDENTITY_DST:
                    std::cerr << "SADB type is: SADB_EXT_IDENTITY_DST" << std::endl;
                    break;
                case SADB_EXT_SENSITIVITY:
                    std::cerr << "SADB type is: SADB_EXT_SENSITIVITY" << std::endl;
                    break;
                case SADB_EXT_PROPOSAL:
                    std::cerr << "SADB type is: SADB_EXT_PROPOSAL" << std::endl;
                    break;
                case SADB_EXT_SUPPORTED_AUTH:
                    std::cerr << "SADB type is: SADB_EXT_SUPPORTED_AUTH" << std::endl;
                    break;
                case SADB_EXT_SUPPORTED_ENCRYPT:
                    std::cerr << "SADB type is: SADB_EXT_SUPPORTED_ENCRYPT" << std::endl;
                    break;
                case SADB_EXT_SPIRANGE:
                    std::cerr << "SADB type is: SADB_EXT_SPIRANGE" << std::endl;
                    break;
                case SADB_X_EXT_KMPRIVATE:
                    std::cerr << "SADB type is SADB_X_EXT_KMPRIVATE" << std::endl;
                    break;
                case SADB_X_EXT_POLICY:
                    std::cerr << "SADB type is SADB_X_EXT_POLICY" << std::endl;
                    break;
                case SADB_X_EXT_SA2:
                    std::cerr << "SADB type is SADB_X_EXT_SA2" << std::endl;
                    break;
                default:
                    std::cerr << "Unknown SADB type" << std::endl;
                    break;
            }
            index += extHeader.sadb_ext_len * 8;
            if(extHeader.sadb_ext_len <= 0)break;
        }

        // * extract from The Association extension (SA)
        config.spi = spi;

        // * ALG id extract from The Association extension (SA)
        // * aalg = authentication algorithm
        // * ealg = encryption algorithm
        // * key extract from key.
        config.aalg = std::make_unique<ESP_AALG>(authAlgId, authKey);
        if(hasEncryptAlgo)
        {
            config.ealg = std::make_unique<ESP_EALG>(encryptAlgId, encryptKey);
        }
        else
        {
            config.ealg = std::make_unique<ESP_EALG>(SADB_EALG_NONE, std::span<uint8_t>{});
        }

        // * extract from The Address extension
        config.local = ipToString(dstAddr);
        config.remote = ipToString(srcAddr);
        // return std::nullopt;
        return config;
    }
    std::cerr << "SADB entry not found." << std::endl;
    return std::nullopt;
    }

    std::ostream &operator<<(std::ostream &os, const ESPConfig &config) {
    os << "------------------------------------------------------------" << std::endl;
    os << "AALG  : ";
    if (!config.aalg->empty()) {
        os << std::left << std::setw(30) << std::setfill(' ') << config.aalg->name();
        os << "HWACCEL: " << config.aalg->provider() << std::endl;
    } else {
        os << "NONE" << std::endl;
    }
    os << "EALG  : ";
    if (!config.ealg->empty()) {
        os << std::left << std::setw(30) << std::setfill(' ') << config.ealg->name();
        os << "HWACCEL: " << config.aalg->provider() << std::endl;
    } else {
        os << "NONE" << std::endl;
    }
    os << "Local : " << config.local << std::endl;
    os << "Remote: " << config.remote << std::endl;
    os << "------------------------------------------------------------";
    return os;
}
