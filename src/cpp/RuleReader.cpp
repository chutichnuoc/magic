#include "../header/RuleReader.h"

std::vector<RuleHeader> get_rules(std::string file_path)
{
    std::vector<RuleHeader> rules;
    std::ifstream infile(file_path);
    std::string line;
    while (getline(infile, line))
    {
        std::istringstream iss(line);
        std::string action, protocol, src_ip, src_port, flow, dst_ip, dst_port;
        if (!(iss >> action >> protocol >> src_ip >> src_port >> flow >> dst_ip >> dst_port))
        {
            iss.clear();
            break;
        }
        RuleHeader rule(action, protocol, src_ip, src_port, dst_ip, dst_port);
        if (line.find('(') != std::string::npos && line.find(')') != std::string::npos)
        {
            std::string option = line.substr(line.find('(') + 1, line.find(')') - line.find('(') - 1);
            if (option.find("time") != std::string::npos)
            {
                std::string time = get_option_value_by_key(option, "time");
                rule.time = std::stoi(time);
            }
            if (option.find("count") != std::string::npos)
            {
                std::string count = get_option_value_by_key(option, "count");
                rule.count = std::stoi(count);
                rule.match_packet_count = false;
            }
        }
        rules.push_back(rule);
    }
    infile.close();
    return rules;
}

std::string get_option_value_by_key(std::string option, std::string key)
{
    std::string value;
    std::string key_extend = key.append(": ");
    int key_extend_length = key_extend.length();
    std::string sub_option = option.substr(option.find(key_extend) + key_extend_length);
    int nIndex = sub_option.find(';');
    value = option.substr(option.find(key_extend) + key_extend_length, nIndex);
    return value;
}