#include "../header/common_util.h"

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
    std::string cpu_idle = exec("top -b -n 1 | grep Cpu | tail -n 1 | awk '{print $8}'");
    replace(cpu_idle.begin(), cpu_idle.end(), ',', '.');
    try
    {
        double cpu_usage = 100 - stod(cpu_idle);
        return cpu_usage;
    }
    catch (std::exception &e)
    {
        return 100;
    }
}

void set_cpu_last_second()
{
    while (true)
    {
        cpu_last_second = get_cpu_usage();
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

double get_cpu_last_second()
{
    return cpu_last_second;
}

void print_app_usage()
{
	printf("Usage: %s [interface] [mode] [config]\n\n", APP_NAME);
	printf("Options: \n");
	printf("    c_mode    	  Capture mode (IPS/IDS)\n");
	printf("    r_mode    	  Running mode (NET/HOST)\n");
	printf("    config    	  Config file\n\n");
	return;
}
