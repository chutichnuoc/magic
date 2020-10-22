#include "../header/ConfigReader.h"

static std::string config_file_path;

void set_config_File_path(std::string path)
{
    config_file_path = path;
}

std::string get_config_value(std::string key)
{
    std::ifstream infile(config_file_path);
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
