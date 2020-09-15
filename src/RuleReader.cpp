#include "RuleReader.h"

std::vector<RuleHeader> getRules(std::string filePath)
{
    std::vector<RuleHeader> rules;
    std::ifstream infile(filePath);
    std::string line;
    while (getline(infile, line))
    {
        std::istringstream iss(line);
        std::string action, protocol, srcIp, srcPort, flow, dstIp, dstPort;
        if (!(iss >> action >> protocol >> srcIp >> srcPort >> flow >> dstIp >> dstPort))
        {
            iss.clear();
            break;
        }
        RuleHeader rule(action, protocol, srcIp, srcPort, dstIp, dstPort);
        if (line.find('(') != std::string::npos && line.find(')') != std::string::npos)
        {
            std::string option = line.substr(line.find('(') + 1, line.find(')') - line.find('(') - 1);
            if (option.find("size") != std::string::npos)
            {
                std::string size = getOptionValueByKey(option, "size");
                rule.size = std::stoi(size);
            }
            if (option.find("time") != std::string::npos)
            {
                std::string time = getOptionValueByKey(option, "time");
                rule.time = std::stoi(time);
            }
            if (option.find("count") != std::string::npos)
            {
                std::string count = getOptionValueByKey(option, "count");
                rule.count = std::stoi(count);
                rule.matchPacketCount = false;
            }
        }
        rules.push_back(rule);
        // rule.toString();
    }
    infile.close();
    return rules;
}

std::string getOptionValueByKey(std::string option, std::string key)
{
    std::string value;
    std::string keyExtend = key.append(": ");
    int keyExtendLength = keyExtend.length();
    std::string subOption = option.substr(option.find(keyExtend) + keyExtendLength);
    int nIndex = subOption.find(';');
    value = option.substr(option.find(keyExtend) + keyExtendLength, nIndex);
    return value;
}