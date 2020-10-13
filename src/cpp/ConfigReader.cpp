#include "../header/ConfigReader.h"

std::string getConfigValue(std::string key)
{
    const std::string filePath = "/home/chutichnuoc/ppp_ids/config/config.ini";

    std::ifstream infile(filePath);
    std::string line;
    while (getline(infile, line))
    {
        int keyIndex = line.find(key);
        if (keyIndex != std::string::npos)
        {
            std::string value = line.substr(keyIndex + key.length() + 3);
            return value;
        }
    }
    return "";
}
