#include "../header/ConfigReader.h"

static std::string configFilePath;

void setConfigFilePath(std::string path)
{
    configFilePath = path;
}

std::string getConfigValue(std::string key)
{
    std::ifstream infile(configFilePath);
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
