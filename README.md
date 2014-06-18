NetMRI-2014-3418
================
InfoBlox Network Automation Metasploit Module

This is a Metasploit module that exploits an OS command injection vulnerability in the InfoBlox Network Automation Products.

Installation:

	git clone https://github.com/depthsecurity/NetMRI-2014-3418.git
	Copy netmri.rb file to Metasploit modules directory (e.g. /root/.msf4/modules/exploits/multi/http/)

Standard Functionality Includes:

	User creation
	Setting password for user
	Adds user to the "wheel" group, commands can be executed as root
	Auto-generation of random username and password values if not specified
	Executes linux payload of choice, tested with reverse meterpreter

Future Functionality:

	Remove SSH dependency, utilize only HTTP for payload transmission.
