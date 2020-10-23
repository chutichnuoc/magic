#include "../header/logger.h"

void log_packet_info(std::string message)
{
    time_t raw_time;
    struct tm *time_info;
    char buffer[80];

    time(&raw_time);
    time_info = localtime(&raw_time);

    strftime(buffer, sizeof(buffer), "%d-%m-%Y %H:%M:%S", time_info);
    std::string curr_time(buffer);

    std::ofstream log_file;

    std::string log_file_path = get_config_value("logFile");
    log_file.open(log_file_path, std::ios_base::app);
    log_file << curr_time << "\t\t" << message << std::endl;
    log_file.close();
}