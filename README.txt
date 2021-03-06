FW6 - Linux High Speed Firewall (FW6)

Author: Asst. Prof. Suchart Khummanee,

Description: FW6 is a high speed firewall that can match any packets against any firewall rule by O(1) worst case access time.
	It is as fast as IPSets - the most of the high speed firewall opensource today - but FW6 can solve limitations of IPSets.
	For example, ip class, group of similar rule, rule conflicts and etc. FW6 disigned from Decision State Diagram (DSD)
	and memory mapping technique. It uses small memory, O(1) of time complexity and no conflicts rule.

Name: FW6 - administration tool for IPv4 packet filtering (High Speed Firewall: FW6)

Synopsis:
 
FW6  --in		define inbound packet flows [required], small letters only
FW6  --out		define outbound packet flows [required], small letters only
FW6 [--srcip]		define source ipv4 address [options], A.B.C.D, where A, B, C, D = 0 - 255, eg., 192.168.1.10
FW6 [--destip]	define destination ipv4 address [options], A.B.C.D, where A, B, C, D = 0 - 255
FW6 [--srcnetmask]	define source ipv4 netmask [options], A.B.C.D, where A, B, C, D = 0 - 255, eg., 255.255.255.0
FW6 [--destnetmask]	define destination ipv4 netmask [options], A.B.C.D, where A, B, C, D = 0 - 255
FW6 [--srcport]	define source port [options], integer only, 0 - 65535
FW6 [--destport]	define destination port [options], integer only, 0 - 65535
FW6 [--proto]		define ipv4 protocol [options], eg., tcp, udp, icmp, all or deny
FW6  --action		define action for filtering a packet, eg., tcp, udp, icmp and all or deny
FW6 [--delete]	delete a firewall rule or all firewall rules
FW6 [--print]		print all firewall rules 
FW6 [--apply]		force user commands (foreground: user space) to the firewall system (background: kernel space)  
FW6 [--help]		help FW6 firewall commands 

Examples:
1. allow all source ip addresses, any source netmask and all source ports to all destination ip addresses, 
   any destination netmask and all destination ports at inbound interface.
   ./FW6 --in --action accept  or 
   ./FW6 --in --srcip any --srcnetmask any --srcport any --destip any --destnemask any --destport any --proto any --action accept
2. drop all source ip addresses, all netmasks and all ports to all destinations at outbound interface.
   ./FW6 --out --action deny

3. drop src ip addresses ranging from 192.168.1.0 - 255, any src ports to a dest ip address 200.0.0.10, dest port 80 at outbound interface.
   ./FW6 --out --srcip 192.168.1.0 --srcnetmask 255.255.255.0 --destip 200.0.0.10 --destnetmask 255.255.255.255 --destport 80 --action deny

4. allow a src ip address 10.10.10.10, a src port 1234 to all dest ip addresses, a protocol udp at inbound interface.
   ./FW6 --in --srcip 10.10.10.10 --srcnetmask 255.255.255.255 --srcport 1234 --proto udp --action accept

5. drop icmp and udp protocol from any source addresses to any destination addresses at inbound interface.
   ./FW6 --in --proto icmp --action deny
   ./FW6 --in --proto udp --action deny

6. allow the dest port number 25, 53 and 80 at outbound interface.
   ./FW6 --out --destport 25 --action accept
   ./FW6 --out --destport 53 --action accept
   ./FW6 --out --destport 80 --action accept

7. drop group of dest ip addresses ranging from 172.16.0.0 - 172.16.255.255, dest port 8080 at inbound interface.
   ./FW6 --in --destip 172.16.0.0 --destnetmask 255.255.0.0 --destport 8080 --action deny

8. print firewall rules
   ./FW6 --print

9. delete any firewall rule, format ./FW6 --delete rule-number
   ./FW6 --delete 1  //delete rule number 1
   ./FW6 --delete all  //delete all rules

10. force user commands to linux system (to active firewall)
    Remask: while user types any input on the console, it will not effect with firewall system. You need to force the commands to
    firewall system by the apply command.
   ./FW6 --apply

11. show a short manual to describe how to firewall working
   ./FW6 --help or
   ./FW6 --?
