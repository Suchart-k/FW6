/*
 * FW6_lkm.h
 *
 *  Created on: Oct 25, 2016
 *      Author: root
 */

#ifndef FW6_LKM_H_
#define FW6_LKM_H_
#endif /* FW6_LKM_H_ */

/* define debug program */
#define _DEBUG				0

/* define in-bound and in-bound packet */
#define _OUT				0
#define _IN					1

/* define detail about procfs */
#define _PROCF_NAME			"FW6"	// name of high speed linux firwall in /proc file
#define _PROCFS_MAX_SIZE 	1800000 // the number of buffer to read/write data with proc file (1 rule uses 90 chars including '\n' bytes, this size for 20,000 rules)
#define _PERMISSION			0644	// permission of proc file directory
#define _EOF				33		// it's '!' symbol at the end of file to show that finished file

/* define matching parameters */
#define _NO_MATCH			0
#define _MATCH				1

/* define TCP/IP and UDP  parameter */
#define _TCP				6
#define _UDP				17
#define _ALL_PROTO			255

/* define detail about high speed linux firewall */
#define _MAX_RULES			65534	// maximum size of high speed firewall rules that can be handled (65535 = 'X' = shared data)
#define _MAX_PORT			65536	// maximum size of high speed firewall ports that can be handled
#define _DONT_CARE			65535	// shared data between all rules
#define _EMPTY				0		// empty data
#define _MAX_IP				4294967295 // maximum size of ipv4 address

/* IP Packing */
#define _DENY_OUT			100		//for denying an outgoing packet (00)
#define _DENY_IN			101		//for denying an incoming packet (01)
#define _ACCEPT_OUT			110		//for accepting an outgoing packet (10)
#define _ACCEPT_IN			111		//for accepting an incoming packet (11)

/* define structure for keeping string rules from user space */
struct rule_list{
	char *info;
};
typedef struct rule_list fw_rule;

struct a_rule{
	unsigned char in_out; // 0 = out, 1 = in
	unsigned short start_dest_port;
	unsigned short stop_dest_port;
	unsigned char start_dest_ip[4];
	unsigned char stop_dest_ip[4];
	unsigned char start_src_ip[4];
	unsigned char stop_src_ip[4];
	unsigned char start_proto;
	unsigned char stop_proto;
	unsigned char action; // 0 = deny, 1 = accept
};
typedef struct a_rule a_rule;

struct node{
	unsigned int start;	//in case of action, it is used for keeping an action 0 = deny, 1 = accept
	unsigned int stop;		//in case of action, it is used for keeping in or out of interface arriving packet
	unsigned int ip_min[4];
	unsigned int ip_max[4];
	struct node *child;		//under node
	struct node *next;		//right node (sibling)
};
typedef struct node node;

/*  Note: C data types
 *  unsigned char 	= 1 byte 	--> 0 - 255
 *  unsigned short 	= 2 bytes 	--> 0 - 65535
 *  unsigned int 	= 4 byte	--> 0 - 4294967296
 *  unsigned long 	= 8 bytes	--> 0 - 18446744073709551616
 * */


