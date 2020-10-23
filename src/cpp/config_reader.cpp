#include "../header/config_reader.h"

static std::string config_file_path;

void set_config_file_path(std::string path)
{
    printf("Setting config file path\n");
    config_file_path = path;
}

std::string get_config_value(std::string key)
{
    std::ifstream infile(config_file_path);
    std::string line;
    while (getline(infile, line))
    {
        int key_index = line.find(key);
        if (key_index != std::string::npos)
        {
            std::string value = line.substr(key_index + key.length() + 3);
            return value;
        }
    }
    return "";
}
