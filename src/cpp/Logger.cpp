#include "../header/Logger.h"

void getCurrentDir()
{
    char cwd[1024];
    chdir("/path/to/change/directory/to");
    getcwd(cwd, sizeof(cwd));
    std::string dir(cwd);
    std::cout << "Current working dir: " << dir << std::endl;
}

void logPacketInfo(std::string message)
{
    time_t rawtime;
    struct tm *timeinfo;
    char buffer[80];

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(buffer, sizeof(buffer), "%d-%m-%Y %H:%M:%S", timeinfo);
    std::string currTime(buffer);

    // getCurrentDir();

    std::ofstream myfile;

    std::string logFile = get_config_value("logFile");
    myfile.open(logFile, std::ios_base::app);
    myfile << currTime << "\t\t" << message << std::endl;
    myfile.close();
}