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

void setup_iptables(std::string interface, std::string mode)
{
	backup_iptables();
	printf("Setting iptables nfqueue\n");
	if (mode.compare("NET") == 0)
	{
		std::string command = "iptables -I FORWARD -j NFQUEUE -i " + interface;
		system(command.c_str());
	}
	else
	{
		std::string command = "iptables -I INPUT -j NFQUEUE -i " + interface;
		system(command.c_str());
		command = "iptables -I OUTPUT -j NFQUEUE";
		system(command.c_str());
	}
}