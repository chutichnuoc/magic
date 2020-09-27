#include "../header/Logger.h"

void logPacketInfo(std::string message)
{
    time_t rawtime;
    struct tm *timeinfo;
    char buffer[80];

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(buffer, sizeof(buffer), "%d-%m-%Y %H:%M:%S", timeinfo);
    std::string currTime(buffer);

    std::ofstream myfile;
    myfile.open("/home/chutichnuoc/ppp_ids/src/out/log.txt", std::ios_base::app);
    myfile << currTime << "\t\t" << message << std::endl;
    myfile.close();
}