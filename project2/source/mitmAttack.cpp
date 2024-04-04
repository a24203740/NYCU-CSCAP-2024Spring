#include <iostream>
#include <string>
#include "../header/mitmAttack.h"

int main()
{
    arpSocket arp;
    arp.createSocket("enp0s17");
    arp.setTimeout(0, 10000); // 0.01 sec
    arp.setSourceAddress("10.0.2.5", "08:00:27:63:76:2d"); // hard coded, change to dynamic later
    for(int i = 1; i <= 254; i++)
    {
        std::string targetIp = "10.0.2." + std::to_string(i);
        std::string mac = arp.getMacAddress(targetIp.c_str(), 1);
        if(mac.empty())
        {
            continue;
        }
        std::cout << targetIp << " : " << mac << std::endl;
    }
}