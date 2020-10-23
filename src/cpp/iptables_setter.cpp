#include "../header/iptables_setter.h"

void backup_iptables()
{
	std::string iptables_file_path = get_config_value("iptablesFile");
	std::string command = "iptables-save > " + iptables_file_path;
	system(command.c_str());
}

void restore_iptables()
{
	std::string iptables_file_path = get_config_value("iptablesFile");
	std::string command = "iptables-restore < " + iptables_file_path;
	system(command.c_str());
}

void setup_iptables(std::string interface)
{
	backup_iptables();
	std::string command = "iptables -I FORWARD -j NFQUEUE -i " + interface;
	system(command.c_str());
}