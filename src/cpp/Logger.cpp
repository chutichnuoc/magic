#include "../header/Logger.h"

void logPacketInfo(std::string message)
{
    time_t now = time(0);
    std::string currentTime(ctime(&now));
    
    std::ofstream myfile;
    myfile.open("/home/chutichnuoc/ppp_ids/src/out/log.txt", std::ios_base::app);
    myfile << currentTime << message << std::endl;
    myfile.close();
}