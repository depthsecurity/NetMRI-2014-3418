NetMRI-CVE-2014-3418 - Metasploit Module
================
InfoBlox Network Automation OS Command Injection Metasploit Module

Product: Network Automation
	NetMRI
	Switch Port Manager
	Automation Change Manager
	Security Device Controller
Vendor: 
	InfoBlox
Vulnerable Version(s):
	6.4.X.X-6.8.4.X
Tested Version: 
	6.8.2.11

Vendor Notification: May 12th, 2014 
Public Disclosure: July 9th, 2014 
Vulnerability Type: OS Command Injection [CWE-78]
CVE Reference: CVE-2014-3418
Discovered and Provided: Nate Kettlewell, Depth Security ( https://www.depthsecurity.com/ )

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
	Proper cleanup on session end, processes do not die
