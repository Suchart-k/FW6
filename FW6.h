/*
 * FW6.h*
 *  Created on: Oct 14, 2016
 *      Author: Suchart Khummanee (khummanee @ gmail.com)
 *      header for FW6 firewall
 */

#include <arpa/inet.h>
//#include <net/if.h>
//#include <net/ethernet.h>
//#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef FW6_H_
#define FW6_H_
#endif /* FW6_H_ */

/* define in-bound and in-bound packet */
#define _OUT				0
#define _IN					1

// IP Addressing & firewall rule
#define _PROTO				12
#define _SRC_IP				13
#define _DST_IP				14
#define _SRC_MASK			15
#define _DEST_MASK			16
#define _SRC_PORT			17
#define _DEST_PORT			18
#define _ACT				19
#define _MAX_IPV4			4294967295
#define _MAX_PORT			65535

/* commands to control firewall */
#define _ADD				30
#define _DEL				31
#define _PRINT				32
#define _APPLY				33
#define _HELP				34
#define _QUEST				35

/* Netfilter hooks */
#define _NF_IP_PRE_ROUTE	40
#define _NF_IP_LOCAL_IN		41
#define _NF_IP_FORWARD		42
#define _NF_IP_LOCAL_OUT	43
#define _NF_IP_POST_ROUTE	44

/* protocols and their header */
#define _ICMP_PROTO			1
#define _IPV4_PROTO			4
#define _TCP_PROTO			6
#define _UDP_PROTO			17
#define _ALL_PROTO			255
#define _TCP				"tcp"
#define _UDP				"udp"
#define _ICMP				"icmp"
#define _ANY				"any"
#define _ALL				"all"
#define _ACCEPT				"accept"
#define _DENY				"deny"
#define _IP_LEN				4
#define _MASK_LEN			4
#define _MAX_PROTO			255

/* define checked value of each field type of firewall rule */
#define _IS_SRC_IP			0
#define _IS_SRC_MASK		1
#define _IS_SRC_PORT		3
#define _IS_DEST_IP			4
#define _IS_DEST_MASK		5
#define _IS_DEST_PORT		6
#define _IS_PROTO			7
#define _IS_ACT				8
#define _ANY				"any"

/* define miscellaneous */
#define _NO					0
#define _YES				1
#define _DEBUG				0	// control for print all data, 0 = no print or 1 = print
#define _FALSE				0
#define _TRUE				1
#define _DELIM 				"."
#define _GREEN   			"\033[32;1m"		/* Bold Green */
#define _BOLDRED     		"\033[1m\033[31m" 	/* Bold Red */
#define _BOLDBLACK   		"\033[1m\033[30m"	/* Bold Black */
#define _BOLDBLUE    		"\033[1m\033[34m"	/* Bold Blue */
#define _RESET   			"\033[0m"			// Reset color
#define _MAX_RULE			65535
#define _EOF				33	// it's '!' symbol at the end of file to show that finished file

/* define file parameters */
#define _O_WRITE			"w"	 //open for writing (file need not exist)
#define _O_READ				"r"	//open for reading
#define _O_READ_WRITE		"r+" //open for reading and writing, start at beginning
#define _O_WRITE_APPEND		"a+" // open for both reading and appending, If the file does not exists, it will be created.
#define _TEST_NAME			"fw.txt"
#define _PROCF_NAME			"/proc/FW6" //"fw.txt"	// /proc/FW6
#define _FW_RULE_NOR_NAME	"firewall_rule.nor"  // plain text firwall rule name
#define _FW_RULE_DSD_NAME	"firewall_rule.dsd" // after convert plain text rule to decision state diagram rule name
#define _FW_RULE_TMP_NAME	"firewall_rule.tmp"
#define _FW_README			"README.txt"
#define _FW_STRUCT			100
#define _CMD_STRUCT			101
#define _NOR_FW_RULE		102
#define _DSD_FW_RULE		103

/* define FDSD (N-ary) tree */
#define _DISJOINT			0
#define _COMP_SUPERSET		1
#define _COMP_SUBSET		2
#define	_SOME_SUBSET		3
#define _INTESECTION		4
#define _NO_CASE			5

/* stack structure */
#define _STACK_MAX			65536

struct data{
	unsigned int start;
	unsigned int stop;
};
typedef struct data data;

struct stack{
	int top;
	data item[_STACK_MAX];
};
typedef struct stack stack;


/* queue structure */
#define _QUEUE_MAX			65536

struct list_node{
	unsigned char case_no;
	struct node *addr;
};
typedef struct list_node lst_node;

struct queue{
	int front;
	int rear;
	int itemCount;
	lst_node item[_QUEUE_MAX];
};
typedef struct queue queue;


/* define structure for delete, print, insert (feature), update (feature) */
static struct control_command {
	unsigned char id;
	char *name;
	char *no;
} contr_cmd;

static struct ipaddrs_struct{
	char *network_ip;
	char *first_ip;
	char *last_ip;
	char *broadcast_ip;
	unsigned int host_count;
	unsigned int prefix;
} ip_struct;

typedef struct DSD_structure{
	unsigned char in_out; // 0 = out, 1 = in
	unsigned int start_src_ip;
	unsigned int stop_src_ip;
	unsigned int start_dest_ip;
	unsigned int stop_dest_ip;
	unsigned short start_src_port;
	unsigned short stop_src_port;
	unsigned short start_dest_port;
	unsigned short stop_dest_port;
	unsigned char start_proto;
	unsigned char stop_proto;
	unsigned char action; // 0 = deny, 1 = accept
} dsd_struct;

static struct firewall_rule_struct {
        int in_out;
        char *src_ip;
        char *src_netmask;
        char *src_port;
        char *dest_ip;
        char *dest_netmask;
        char *dest_port;
        char *proto;	// can be TCP/UDP/ICMP
        char *action;	// DENY or ACCEPT
        unsigned char hook_id;
        int rule_num;
        unsigned long   packet_count;
} firewall_rule;

/* declare N-ary tree for containing FDSD firewall */

struct node{
	unsigned int start;	//in case of action, it is used for keeping an action 0 = deny, 1 = accept
	unsigned int stop;		//in case of action, it is used for keeping in or out of interface arriving packet
	struct node *child;
	struct node *next;
};
typedef struct node node;

struct sub_result_list{
	unsigned char case_no;
	struct node *addr;
	struct sub_result_list *next;
};
typedef struct sub_result_list sublist_result;

static struct subtract_struct{
	unsigned char case_no;
	unsigned int start1;
	unsigned int stop1;
	unsigned int start2;
	unsigned int stop2;
} sub_result;


