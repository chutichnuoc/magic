#include "../header/Logger.h"

void log_packet_info(std::string message)
{
    time_t raw_time;
    struct tm *time_info;
    char buffer[80];

    time(&raw_time);
    time_info = localtime(&raw_time);

    strftime(buffer, sizeof(buffer), "%d-%m-%Y %H:%M:%S", time_info);
    std::string currTime(buffer);

    std::ofstream myfile;

    std::string logFile = get_config_value("logFile");
    myfile.open(logFile, std::ios_base::app);
    myfile << currTime << "\t\t" << message << std::endl;
    myfile.close();
}