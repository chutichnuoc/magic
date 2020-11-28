#include "../header/common_util.h"

std::string packet_info_to_string(std::string protocol, std::string src_ip, std::string src_port, std::string dst_ip, std::string dst_port, bool drop, std::string reason)
{
    std::string info = "";
    info += protocol + "    ";
    if (protocol.compare("icmp") == 0)
    {
        info += src_ip + " -> " + dst_ip;
    }
    else
    {
        info += src_ip + ":" + src_port + " -> " + dst_ip + ":" + dst_port;
    }
    if (drop)
    {
        info += " (dropped)";
    }
    info += " " + reason;
    return info;    
}

std::string exec(const char *cmd)
{
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe)
    {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
    {
        result += buffer.data();
    }
    return result;
}

double get_cpu_usage()
{
    std::string cpu_idle = exec("top -b -n 1 | grep Cpu | tail -n 1 | awk '{print $8}'");
    replace(cpu_idle.begin(), cpu_idle.end(), ',', '.');
    try
    {
        double cpu_usage = 100 - stod(cpu_idle);
        return cpu_usage;
    }
    catch(std::exception& e)
    {
        return 100;
    }
}