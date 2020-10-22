#include "../header/CommonUtil.h"

std::string packet_info_to_string(std::string protocol, std::string src_ip, std::string src_port, std::string dst_ip, std::string dst_port, bool drop)
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
    return stod(exec("grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}'"));
}