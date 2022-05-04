/*
 * FW6_lkm.c
 *
 *  Created on: Oct 25, 2016
 *      Author: root
 */

#include <linux/module.h> 		/* Specifically, a module */
#include <linux/kernel.h>		/* We're doing kernel work */
#include <linux/proc_fs.h>		/* Necessary because we use proc fs */
#include <linux/list.h>
#include <asm/uaccess.h>		/* for copy_*_user */
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/vmalloc.h>

#include "FW6_lkm.h"

#define TRUE 	1
#define FALSE 	0


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("High Speed Linux Firewall");
MODULE_AUTHOR("Suchart Khummanee");

//control firewall working or non-working
static unsigned char FW6_FILTER_ACTIVE = FALSE;	//0 = rule matching no start, 1 = rule matching start
static unsigned char FW6_WRITE_OK = FALSE;	//0 = writing file not finished , 1 = finished

//the parameters use for procfs
static struct proc_dir_entry *procf_entry;
static char *procfs_buffer;						//The buffer used to store temporary firewall rules from user space
static char *procfs_buffer_fw;					//buffer for maintaining firewall rules
static unsigned short rule_count;				//hold the number of firewall rules
static unsigned short rule_count_tmp;				//hold the number of firewall rules
static unsigned long procfs_buffer_size = 0;	//The size of the buffer
static unsigned long procfs_buffer_index = 0;
static char *sub_rule;
static char **rules;
static node *root;
static int dport_page_size, dip_page_size, sip_page_size, proto_page_size;

//the structure used to register the function
static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho_out;


// parameters for preparing IP Packing
static unsigned short DEST_PORT[_MAX_PORT] = {0};
static long **RLT_DEST_IP_O1;	//row lookup tab stores left most octet of dest_ip, eg. 1.2.3.4 (keeps 1)
static long **RLT_DEST_IP_O2;
static long **RLT_DEST_IP_O3;
static long **RLT_DEST_IP_O4;	//stores right most octet of dest_ip (keeps 4)
static unsigned short *D_DEST_IP_O1;	//1-D array stores compacted data from array 2-D dest_ip
static unsigned short *D_DEST_IP_O2;
static unsigned short *D_DEST_IP_O3;
static unsigned short *D_DEST_IP_O4;
static long **RLT_SRC_IP_O1;
static long **RLT_SRC_IP_O2;
static long **RLT_SRC_IP_O3;
static long **RLT_SRC_IP_O4;
static unsigned short *D_SRC_IP_O1;
static unsigned short *D_SRC_IP_O2;
static unsigned short *D_SRC_IP_O3;
static unsigned short *D_SRC_IP_O4;
static long **RLT_PROTO;
static unsigned char *D_PROTO;
static unsigned long count_slot_dip[4] = {0};	//count_page_dip[0] keeps OCT1 (left most), OCT2, OCT3 and OCT4 respectively
static unsigned long count_slot_sip[4] = {0};
static unsigned long count_slot_proto = 0;
static unsigned long count_buff = 0;

/* declare function of kernel module header prototypes of high speed linux firewall */
int FW6_init_module(void);
void FW6_init_misc(void);
void FW6_cleanup_misc(void);
void FW6_cleanup_module(void);
int init_read_write_module(void);
int init_hook_module(void);
void cleanup_hook_module(void);
void cleanup_read_write_module(void);
int procf_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data);
int procf_write(struct file *filp, const char *buffer, unsigned long count, void *data);
void build_FDSD_tree(void);
unsigned short port_str_to_int(char *port_str);
void ip_str_to_byte_array(unsigned char *ipx, char *ip_str);
void int_to_IP_byte_array(unsigned short *buffer, unsigned int ip_start);
unsigned char oct_str_to_int(char *port_str);
unsigned int convert_str_to_int(char *str);
node *new_node(unsigned int start, unsigned int stop);
node *add_sibling(node *n, unsigned int start, unsigned int stop);
node *add_child(node *n, unsigned int start, unsigned int stop);
node *is_member(node *n, unsigned int start, unsigned int stop);
void show_FDSD_tree(node *n);
char *convert_int_to_IP(unsigned int ip);
void preprocess_IP_packing(node *n);
void count_slot_octx(unsigned int *buffer, unsigned int *ip_start, unsigned int *ip_stop);
void ip_range(unsigned int *buffer, unsigned int ip_start, unsigned int ip_stop);
void map_dest_port(unsigned int start, unsigned int stop, unsigned short page);
void packing(void);
int IP_PACKING(node *n);
void show_IP_packed(void);
node *free_FDSD_tree(node *n);
void preorder_traversal(node *n);
unsigned int FW6_inbound_filter(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));
unsigned int FW6_outbound_filter(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));
int matching_packet(struct sk_buff *skb);
void activate_packet_filtering(int state);
long **get_mem(int rows, int cols);
void set_zero_mem(long** table, int rows, int cols);
void set_zero_port(void);
void get_min(unsigned int *buffer, unsigned int ip_start, unsigned int ip_stop);
void get_max(unsigned int *buffer, unsigned int ip_start, unsigned int ip_stop);

/*--------------------------------------- all functions -------------------------------------*/

long **get_mem(int rows, int cols){ /* Allocate the array */
	long i, **table;
	table = vmalloc(rows * sizeof(long *));
	for(i = 0 ; i < rows ; i++)
		table[i] = vmalloc( cols * sizeof(long) );
	return table;
}

void set_zero_mem(long** table, int rows, int cols){
	int i, j;
	for(i = 0; i < rows; i++)
		for(j = 0; j < cols; j++)
			table[i][j] = 0;
}

void set_zero_port(){
	int i;
	for(i = 0; i < _MAX_PORT; i++){
		DEST_PORT[i] = 0;
	}
}

void preorder_traversal(node *n){
	if(n == NULL) return;

	printk("%u, %u\n",n->start, n->stop);
	preorder_traversal(n->child);
	preorder_traversal(n->next);
}

void ip_range(unsigned int *buffer, unsigned int ip_start, unsigned int ip_stop){
	unsigned int bytes1[4], bytes2[4];
	bytes1[3] = ip_start & 0xFF;
	bytes1[2] = (ip_start >> 8) & 0xFF;
	bytes1[1] = (ip_start >> 16) & 0xFF;
	bytes1[0] = (ip_start >> 24) & 0xFF;
	bytes2[3] = ip_stop & 0xFF;
	bytes2[2] = (ip_stop >> 8) & 0xFF;
	bytes2[1] = (ip_stop >> 16) & 0xFF;
	bytes2[0] = (ip_stop >> 24) & 0xFF;

	if(bytes1[0] > bytes2[0]){
		buffer[0] = bytes2[0];
		buffer[1] = bytes1[0];
	}else {
		buffer[0] = bytes1[0];	//start[otc1]
		buffer[1] = bytes2[0];	//stop[otc1]
	}

	if(bytes1[1] > bytes2[1]){
		buffer[2] = bytes2[1];
		buffer[3] = bytes1[1];
	}else {
		buffer[2] = bytes1[1];
		buffer[3] = bytes2[1];
	}

	if(bytes1[2] > bytes2[2]){
		buffer[4] = bytes2[2];
		buffer[5] = bytes1[2];
	}else {
		buffer[4] = bytes1[2];
		buffer[5] = bytes2[2];
	}

	if(bytes1[3] > bytes2[3]){
		buffer[6] = bytes2[3];
		buffer[7] = bytes1[3];
	}else {
		buffer[6] = bytes1[3];	//start[otc4]
		buffer[7] = bytes2[3];	//stop[otc4]
	}

	//printk("oct1 start/stop = [%u, %u], oct2 start/stop = [%u, %u], oct3 start/stop = [%u, %u], oct4 start/stop = [%u, %u]\n",
	//		buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7]);

	return;
}

void int_to_IP_byte_array(unsigned short *buffer, unsigned int ip_start){
	buffer[3] = ip_start & 0xFF;
	buffer[2] = (ip_start >> 8) & 0xFF;
	buffer[1] = (ip_start >> 16) & 0xFF;
	buffer[0] = (ip_start >> 24) & 0xFF;
	return;
}

void get_min(unsigned int *buffer, unsigned int ip_start, unsigned int ip_stop){
	unsigned int bytes1[4], bytes2[4];
		bytes1[3] = ip_start & 0xFF;
		bytes1[2] = (ip_start >> 8) & 0xFF;
		bytes1[1] = (ip_start >> 16) & 0xFF;
		bytes1[0] = (ip_start >> 24) & 0xFF;
		bytes2[3] = ip_stop & 0xFF;
		bytes2[2] = (ip_stop >> 8) & 0xFF;
		bytes2[1] = (ip_stop >> 16) & 0xFF;
		bytes2[0] = (ip_stop >> 24) & 0xFF;

		if(bytes1[3] < bytes2[3]){
			buffer[3] = bytes1[3];
		}else buffer[3] = bytes2[3];

		if(bytes1[2] < bytes2[2]){
			buffer[2] = bytes1[2];
		}else buffer[2] = bytes2[2];

		if(bytes1[1] < bytes2[1]){
			buffer[1] = bytes1[1];
		}else buffer[1] = bytes2[1];

		if( bytes1[0] < bytes2[0]){
			buffer[0] = bytes1[0];
		}else buffer[0] = bytes2[0];

	return;
}

void get_max(unsigned int *buffer, unsigned int ip_start, unsigned int ip_stop){
	unsigned int bytes1[4], bytes2[4];
		bytes1[3] = ip_start & 0xFF;
		bytes1[2] = (ip_start >> 8) & 0xFF;
		bytes1[1] = (ip_start >> 16) & 0xFF;
		bytes1[0] = (ip_start >> 24) & 0xFF;
		bytes2[3] = ip_stop & 0xFF;
		bytes2[2] = (ip_stop >> 8) & 0xFF;
		bytes2[1] = (ip_stop >> 16) & 0xFF;
		bytes2[0] = (ip_stop >> 24) & 0xFF;

		if(bytes1[3] > bytes2[3]){
			buffer[3] = bytes1[3];
		}else buffer[3] = bytes2[3];

		if(bytes1[2] > bytes2[2]){
			buffer[2] = bytes1[2];
		}else buffer[2] = bytes2[2];

		if(bytes1[1] > bytes2[1]){
			buffer[1] = bytes1[1];
		}else buffer[1] = bytes2[1];

		if( bytes1[0] > bytes2[0]){
			buffer[0] = bytes1[0];
		}else buffer[0] = bytes2[0];

	return;
}

void count_slot_octx(unsigned int *buffer, unsigned int *ip_start, unsigned int *ip_stop){
	if(ip_start[3] > ip_stop[3]){
		buffer[3] = ip_start[3] - ip_stop[3] + 1;
	}else buffer[3] = ip_stop[3] - ip_start[3] + 1;

	if(ip_start[2] > ip_stop[2]){
		buffer[2] = ip_start[2] - ip_stop[2] + 1;
	}else buffer[2] = ip_stop[2] - ip_start[2] + 1;

	if(ip_start[1] > ip_stop[1]){
		buffer[1] = ip_start[1] - ip_stop[1] + 1;
	}else buffer[1] = ip_stop[1] - ip_start[1] + 1;

	if( ip_start[0] > ip_stop[0]){
		buffer[0] = ip_start[0] - ip_stop[0] + 1;
	}else buffer[0] = ip_stop[0] - ip_start[0] + 1;

	return;
}

char *convert_int_to_IP(unsigned int ip){
	char *buffer;
	unsigned char bytes[4];
	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;
	buffer = vmalloc((sizeof(char) * 8));
	sprintf(buffer, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
	return buffer;
}

void ip_str_to_byte_array(unsigned char *ipx, char *ip_str){
	char *found;
	int count = 0;
	while((found = strsep(&ip_str, ".")) != NULL){
		//printk("%s\n", found);
		if(count == 0) ipx[0] = oct_str_to_int(found);
		else if(count == 1) ipx[1] = oct_str_to_int(found);
		else if(count == 2) ipx[2] = oct_str_to_int(found);
		else if(count == 3) ipx[3] = oct_str_to_int(found);
		count++;
	}
	return;
}

unsigned char oct_str_to_int(char *oct_str){
	unsigned char oct = 0;
	unsigned char k = 0;
	if (oct_str == NULL){
		return 0;
	}
	while(oct_str[k] != '\0'){
		oct = oct * 10 + (oct_str[k] - '0');
		++k;
	}
	return oct;
}

unsigned short port_str_to_int(char *port_str){
	unsigned short port = 0;
	unsigned short k = 0;
	if (port_str == NULL){
		return 0;
	}
	while(port_str[k] != '\0'){
		port = port * 10 + (port_str[k] - '0');
		++k;
	}
	return port;
}

unsigned int convert_str_to_int(char *str){
	unsigned int num = 0;
	unsigned int k = 0;
	if (str == NULL){
		return 0;
	}
	while(str[k] != '\0'){
		num = num * 10 + (str[k] - '0');
		++k;
	}
	return num;
}

node *is_member(node *n, unsigned int start, unsigned int stop){
	node *x = n;
	if(x == NULL) return NULL;

	while(x){
		if(x->start == start && x->stop == stop){
			return x;
		}
		x = x->next;
	}

	return NULL;
}

node *new_node(unsigned int start, unsigned int stop){
	node *new_node = vmalloc(sizeof(node));
	if(new_node) {
		new_node->next = NULL;
	    new_node->child = NULL;
	    new_node->start = start;
	    new_node->stop = stop;
	    memset(new_node->ip_min, 0, 4 * sizeof(unsigned short));
	    memset(new_node->ip_max, 0, 4 * sizeof(unsigned short));
	    //new_node->ip_min[0] = 0; new_node->ip_min[1] = 0; new_node->ip_min[2] = 0; new_node->ip_min[3] = 0;
	    //new_node->ip_max[0] = 0; new_node->ip_max[1] = 0; new_node->ip_max[2] = 0; new_node->ip_max[3] = 0;
	}
	return new_node;
}

node *add_sibling(node *n, unsigned int start, unsigned int stop){
	node *x = n;
	if(x == NULL)
		return NULL;

	while (x->next)
		x = x->next;

	return (x->next = new_node(start, stop));
}

node *add_child(node *n, unsigned int start, unsigned int stop){
	node *x = n;
	if(x == NULL)
		return NULL;

	while (x->child)
		x = x->child;

	return (x->child = new_node(start, stop));

}

void map_dest_port(unsigned int start, unsigned int stop, unsigned short page){
	unsigned int i;
	for(i = start; i <= stop; i++){
		if(DEST_PORT[i] == 0){
			DEST_PORT[i] = page;
		}
	}
	return;
}

void show_FDSD_tree(node *n){
	int i = 0;
	node *dest_port, *dest_ip, *src_ip, *proto, *act;
	dest_port = n;
	while(dest_port){
		dest_ip = dest_port->child;
		while(dest_ip){
			src_ip = dest_ip->child;
			while(src_ip){
				proto = src_ip->child;
				while(proto){
					act = proto->child;
					while(act){
						i++;
						//printk("%u %u %u %u %u %u %u %u %u %u\n", act->stop,
						//		dest_port->start, dest_port->stop,
						//		dest_ip->start, dest_ip->stop,
						//		src_ip->start, src_ip->stop,
						//		proto->start, proto->stop,
						//		act->start);
						printk("%u %u %u %s %s %s %s %u %u %u\n", act->stop,
								dest_port->start, dest_port->stop,
								convert_int_to_IP(dest_ip->start), convert_int_to_IP(dest_ip->stop),
								convert_int_to_IP(src_ip->start), convert_int_to_IP(src_ip->stop),
								proto->start, proto->stop,
								act->start);
						//printk("------------------------------------------\n");

						act = act->next;
					}
					proto = proto->next;
				}
				src_ip = src_ip->next;
			}
			dest_ip = dest_ip->next;
		}
		dest_port = dest_port->next;
	}
	printk("FW6: firewall rules after FDSD processing is %d rules.\n", i);
}

void preprocess_IP_packing(node *n){
	node *dest_port, *dest_ip, *src_ip, *proto, *act;
	unsigned int dip_min[4] = {0}, dip_max[4] = {0};
	unsigned int sip_min[4] = {0}, sip_max[4] = {0};
	unsigned int proto_min = 0, proto_max = 0;
	unsigned int buff[4];
	unsigned long memsize;
	rule_count = 0;

	dport_page_size = 0, dip_page_size = 0, sip_page_size = 0, proto_page_size = 0;
	//int cp_dport = 0, cp_dip = 0, cp_sip = 0, cp_pro = 0;  //cp_x = count page each FDSD level
	dest_port = n;
	memset(count_slot_dip, _EMPTY, 4 * sizeof(unsigned long));
	memset(count_slot_sip, _EMPTY, 4 * sizeof(unsigned long));
	count_slot_proto = 0;

	printk(KERN_INFO "FW6: preprocess IP packing function has called.\n");

	while(dest_port){
		dest_ip = dest_port->child;
		get_min(buff, dest_ip->start, dest_ip->stop);
		dip_min[0] = buff[0]; dip_min[1] = buff[1]; dip_min[2] = buff[2]; dip_min[3] = buff[3];
		get_max(buff, dest_ip->start, dest_ip->stop);
		dip_max[0] = buff[0]; dip_max[1] = buff[1]; dip_max[2] = buff[2]; dip_max[3] = buff[3];

		dport_page_size++;

		while(dest_ip){
			src_ip = dest_ip->child;
			get_min(buff, dest_ip->start, dest_ip->stop);
			if(buff[0] < dip_min[0]) dip_min[0] = buff[0];
			if(buff[1] < dip_min[1]) dip_min[1] = buff[1];
			if(buff[2] < dip_min[2]) dip_min[2] = buff[2];
			if(buff[3] < dip_min[3]) dip_min[3] = buff[3];

			get_max(buff, dest_ip->start, dest_ip->stop);
			if(buff[0] > dip_max[0]) dip_max[0] = buff[0];
			if(buff[1] > dip_max[1]) dip_max[1] = buff[1];
			if(buff[2] > dip_max[2]) dip_max[2] = buff[2];
			if(buff[3] > dip_max[3]) dip_max[3] = buff[3];

			get_min(buff, src_ip->start, src_ip->stop);
			sip_min[0] = buff[0]; sip_min[1] = buff[1]; sip_min[2] = buff[2]; sip_min[3] = buff[3];
			get_max(buff, src_ip->start, src_ip->stop);
			sip_max[0] = buff[0]; sip_max[1] = buff[1]; sip_max[2] = buff[2]; sip_max[3] = buff[3];

			dip_page_size++;

			while(src_ip){
				proto = src_ip->child;
				get_min(buff, src_ip->start, src_ip->stop);
				if(buff[0] < sip_min[0]) sip_min[0] = buff[0];
				if(buff[1] < sip_min[1]) sip_min[1] = buff[1];
				if(buff[2] < sip_min[2]) sip_min[2] = buff[2];
				if(buff[3] < sip_min[3]) sip_min[3] = buff[3];

				get_max(buff, src_ip->start, src_ip->stop);
				if(buff[0] > sip_max[0]) sip_max[0] = buff[0];
				if(buff[1] > sip_max[1]) sip_max[1] = buff[1];
				if(buff[2] > sip_max[2]) sip_max[2] = buff[2];
				if(buff[3] > sip_max[3]) sip_max[3] = buff[3];

				proto_min = proto->start;
				proto_max = proto->stop;
				sip_page_size++;

				while(proto){
					act = proto->child;
					if(proto->start < proto_min) proto_min = proto->start;
					if(proto->stop > proto_max) proto_max = proto->stop;
					proto_page_size++;

					while(act){
						// noting to do
						rule_count++;
						act = act->next;
					}
					proto = proto->next;
				}
				src_ip->ip_min[3] = proto_min;
				src_ip->ip_max[3] = proto_max;
				//printk("proto min/max = %u/%u\n", src_ip->ip_min[3], src_ip->ip_max[3]);
				src_ip = src_ip->next;
			}
			dest_ip->ip_min[0] = sip_min[0]; dest_ip->ip_min[1] = sip_min[1]; dest_ip->ip_min[2] = sip_min[2]; dest_ip->ip_min[3] = sip_min[3];
			dest_ip->ip_max[0] = sip_max[0]; dest_ip->ip_max[1] = sip_max[1]; dest_ip->ip_max[2] = sip_max[2]; dest_ip->ip_max[3] = sip_max[3];
			//printk("sip min/max = [%u|%u|%u|%u]/[%u|%u|%u|%u]\n", dest_ip->ip_min[0], dest_ip->ip_min[1], dest_ip->ip_min[2], dest_ip->ip_min[3], dest_ip->ip_max[0], dest_ip->ip_max[1], dest_ip->ip_max[2], dest_ip->ip_max[3]);
			dest_ip = dest_ip->next;
		}
		dest_port->ip_min[0] = dip_min[0]; dest_port->ip_min[1] = dip_min[1]; dest_port->ip_min[2] = dip_min[2]; dest_port->ip_min[3] = dip_min[3];
		dest_port->ip_max[0] = dip_max[0]; dest_port->ip_max[1] = dip_max[1]; dest_port->ip_max[2] = dip_max[2]; dest_port->ip_max[3] = dip_max[3];
		//printk("dip min/max = [%u|%u|%u|%u]/[%u|%u|%u|%u]\n", dest_port->ip_min[0], dest_port->ip_min[1], dest_port->ip_min[2], dest_port->ip_min[3], dest_port->ip_max[0], dest_port->ip_max[1], dest_port->ip_max[2], dest_port->ip_max[3]);
		dest_port = dest_port->next;
	}

	dport_page_size++;	// increase page count by 1 because of firewall rule starting with rule number 1, so page 0 is not use
	dip_page_size++;
	sip_page_size++;
	proto_page_size++;
	printk("dport_page_size = %d, dip = %d, sip = %d, pro = %d\n", dport_page_size, dip_page_size, sip_page_size, proto_page_size);

	// calculate size of member in each page
	dest_port = n;
	while(dest_port){
		dest_ip = dest_port->child;
		count_slot_octx(buff, dest_port->ip_max, dest_port->ip_min);
		count_slot_dip[0] += buff[0];		//for octet 1 (left most)
		count_slot_dip[1] += buff[1];
		count_slot_dip[2] += buff[2];
		count_slot_dip[3] += buff[3];		//for octet 4 (right most)

		while(dest_ip){
			src_ip = dest_ip->child;
			count_slot_octx(buff, dest_ip->ip_max, dest_ip->ip_min);
			count_slot_sip[0] += buff[0];
			count_slot_sip[1] += buff[1];
			count_slot_sip[2] += buff[2];
			count_slot_sip[3] += buff[3];

			while(src_ip){
				count_slot_proto += (src_ip->ip_max[3] - src_ip->ip_min[3]) + 1;
				//printk("proto max - min = (%u - %u)\n", src_ip->ip_max[3], src_ip->ip_min[3]);
				src_ip = src_ip->next;
			}

			dest_ip = dest_ip->next;
		}

		dest_port = dest_port->next;
	}

	printk("count slot sip [0-4] = [%ld, %ld, %ld, %ld]\n", count_slot_sip[0], count_slot_sip[1], count_slot_sip[2], count_slot_sip[3]);
	printk("count slot dip [0-4] = [%ld, %ld, %ld, %ld]\n", count_slot_dip[0], count_slot_dip[1], count_slot_dip[2], count_slot_dip[3]);
	printk("count slot proto = %ld\n", count_slot_proto);

	// allocate memory for RLT and 1-D array for keeping data of dest_ip
	RLT_DEST_IP_O1 = get_mem(2, dport_page_size);	//first row for keeping start page, second row for maintaining stop page
	RLT_DEST_IP_O2 = get_mem(2, dport_page_size);
	RLT_DEST_IP_O3 = get_mem(2, dport_page_size);
	RLT_DEST_IP_O4 = get_mem(2, dport_page_size);
	set_zero_mem(RLT_DEST_IP_O1, 2, dport_page_size);
	set_zero_mem(RLT_DEST_IP_O2, 2, dport_page_size);
	set_zero_mem(RLT_DEST_IP_O3, 2, dport_page_size);
	set_zero_mem(RLT_DEST_IP_O4, 2, dport_page_size);
	D_DEST_IP_O1 = vmalloc((count_slot_dip[0]) * sizeof(unsigned short));
	D_DEST_IP_O2 = vmalloc((count_slot_dip[1]) * sizeof(unsigned short));
	D_DEST_IP_O3 = vmalloc((count_slot_dip[2]) * sizeof(unsigned short));
	D_DEST_IP_O4 = vmalloc((count_slot_dip[3]) * sizeof(unsigned short));
	memset(D_DEST_IP_O1, _EMPTY, (count_slot_dip[0]) * sizeof(unsigned short));
	memset(D_DEST_IP_O2, _EMPTY, (count_slot_dip[1]) * sizeof(unsigned short));
	memset(D_DEST_IP_O3, _EMPTY, (count_slot_dip[2]) * sizeof(unsigned short));
	memset(D_DEST_IP_O4, _EMPTY, (count_slot_dip[3]) * sizeof(unsigned short));

	// allocate memory for RLT and 1-D array for keeping data of src_ip
	RLT_SRC_IP_O1 = get_mem(2, dip_page_size);
	RLT_SRC_IP_O2 = get_mem(2, dip_page_size);
	RLT_SRC_IP_O3 = get_mem(2, dip_page_size);
	RLT_SRC_IP_O4 = get_mem(2, dip_page_size);
	set_zero_mem(RLT_SRC_IP_O1, 2, dip_page_size);
	set_zero_mem(RLT_SRC_IP_O2, 2, dip_page_size);
	set_zero_mem(RLT_SRC_IP_O3, 2, dip_page_size);
	set_zero_mem(RLT_SRC_IP_O4, 2, dip_page_size);
	D_SRC_IP_O1 = vmalloc(count_slot_sip[0] * sizeof(unsigned short));
	D_SRC_IP_O2 = vmalloc(count_slot_sip[1] * sizeof(unsigned short));
	D_SRC_IP_O3 = vmalloc(count_slot_sip[2] * sizeof(unsigned short));
	D_SRC_IP_O4 = vmalloc(count_slot_sip[3] * sizeof(unsigned short));
	memset(D_SRC_IP_O1, _EMPTY, count_slot_sip[0] * sizeof(unsigned short));
	memset(D_SRC_IP_O2, _EMPTY, count_slot_sip[1] * sizeof(unsigned short));
	memset(D_SRC_IP_O3, _EMPTY, count_slot_sip[2] * sizeof(unsigned short));
	memset(D_SRC_IP_O4, _EMPTY, count_slot_sip[3] * sizeof(unsigned short));

	// allocate memory for RLT and 1-D array for keeping data of proto
	RLT_PROTO = get_mem(2, sip_page_size);
	set_zero_mem(RLT_PROTO, 2,  sip_page_size);
	D_PROTO = vmalloc(count_slot_proto * sizeof(unsigned char));
	memset(D_PROTO, _EMPTY, count_slot_proto * sizeof(unsigned char));

	printk(KERN_INFO "FW6: preprocessing data before packing (OK).\n");
	memsize = ((dport_page_size * 2 * 8 * 4) + (sip_page_size * 2 * 8 * 4) + (proto_page_size * 2 * 8) +
			(count_slot_dip[0] * 2) + (count_slot_dip[1] * 2) + (count_slot_dip[2] * 2) + (count_slot_dip[3] * 2) +
			(count_slot_sip[0] * 2) + (count_slot_sip[1] * 2) + (count_slot_sip[2] * 2) + (count_slot_sip[0] * 2) +
			(count_slot_proto)) / 1000;
	printk(KERN_INFO "FW6: the memory size was allocated for packing is %lu KB.\n", memsize);
	return;
}


int IP_PACKING(node *n){
	node *dest_port, *dest_ip, *src_ip, *proto, *act;
	int cp_dport = 0, cp_dip = 0, cp_sip = 0, cp_pro = 0;
	unsigned int buff[4];
	unsigned int buff_r[8];
	long dip_index0 = 0, dip_index1 = 0, dip_index2 = 0, dip_index3 = 0;
	long sip_index0 = 0, sip_index1 = 0, sip_index2 = 0, sip_index3 = 0;
	long proto_index = 0;
	int i;
	dest_port = n;

	printk(KERN_INFO "FW6: IP packing function has called.\n");

	set_zero_port();

	while(dest_port){	//mapping dest_port N-array tree to 1-D array, named DEST_PORT
		cp_dport++;
		map_dest_port(dest_port->start, dest_port->stop, cp_dport);

		dest_ip = dest_port->child;

		RLT_DEST_IP_O1[0][cp_dport] = dip_index0 - dest_port->ip_min[0];
		RLT_DEST_IP_O2[0][cp_dport] = dip_index1 - dest_port->ip_min[1];
		RLT_DEST_IP_O3[0][cp_dport] = dip_index2 - dest_port->ip_min[2];
		RLT_DEST_IP_O4[0][cp_dport] = dip_index3 - dest_port->ip_min[3];

		RLT_DEST_IP_O1[1][cp_dport] = dest_port->ip_max[0];
		RLT_DEST_IP_O2[1][cp_dport] = dest_port->ip_max[1];
		RLT_DEST_IP_O3[1][cp_dport] = dest_port->ip_max[2];
		RLT_DEST_IP_O4[1][cp_dport] = dest_port->ip_max[3];

		while(dest_ip){	//mapping dest_ip N-array tree to RLT (oct1, oct2, oct3 and oct4) and 1-D array, named D_DEST_IP_O1, O2, O3 and O4
			cp_dip++;
			src_ip = dest_ip->child;

			ip_range(buff_r, dest_ip->start, dest_ip->stop);
			//printk("--> (%u, %u), (%u, %u), (%u, %u), (%u, %u)\n", buff_r[0], buff_r[1], buff_r[2], buff_r[3], buff_r[4], buff_r[5], buff_r[6], buff_r[7]);
			for(i = buff_r[0]; i <= buff_r[1]; i++){
				if(D_DEST_IP_O1[RLT_DEST_IP_O1[0][cp_dport] + i] == _EMPTY){
					D_DEST_IP_O1[RLT_DEST_IP_O1[0][cp_dport] + i] = cp_dip;
					//dip_index1++;
				}else if(D_DEST_IP_O1[RLT_DEST_IP_O1[0][cp_dport] + i] == _DONT_CARE){
					//nothing to do, because otc1 is don't care term
				}else if(D_DEST_IP_O1[RLT_DEST_IP_O1[0][cp_dport] + i] == cp_dip){
					//nothing to do, because it's same path
				}else{
					D_DEST_IP_O1[RLT_DEST_IP_O1[0][cp_dport] + i] = _DONT_CARE;
				}
			}

			for(i = buff_r[2]; i <= buff_r[3]; i++){
				if(D_DEST_IP_O2[RLT_DEST_IP_O2[0][cp_dport] + i] == _EMPTY){
					D_DEST_IP_O2[RLT_DEST_IP_O2[0][cp_dport] + i] = cp_dip;
					//dip_index2++;
				}else if(D_DEST_IP_O2[RLT_DEST_IP_O2[0][cp_dport] + i] == _DONT_CARE){
					//nothing to do, because oct2 is don't care term
				}else if(D_DEST_IP_O2[RLT_DEST_IP_O2[0][cp_dport] + i] == cp_dip){
					//nothing to do, because it's same path
				}else{
					D_DEST_IP_O2[RLT_DEST_IP_O2[0][cp_dport] + i] = _DONT_CARE;
				}
			}

			for(i = buff_r[4]; i <= buff_r[5]; i++){
				if(D_DEST_IP_O3[RLT_DEST_IP_O3[0][cp_dport] + i] == _EMPTY){
					D_DEST_IP_O3[RLT_DEST_IP_O3[0][cp_dport] + i] = cp_dip;
					//dip_index3++;
				}else if(D_DEST_IP_O3[RLT_DEST_IP_O3[0][cp_dport] + i] == _DONT_CARE){
					//nothing to do, because oct3 is don't care term
				}else if(D_DEST_IP_O3[RLT_DEST_IP_O3[0][cp_dport] + i] == cp_dip){
					//nothing to do, because it's same path
				}else{
					D_DEST_IP_O3[RLT_DEST_IP_O3[0][cp_dport] + i] = _DONT_CARE;
				}
			}

			for(i = buff_r[6]; i <= buff_r[7]; i++){
				if(D_DEST_IP_O4[RLT_DEST_IP_O4[0][cp_dport] + i] == _EMPTY){
					D_DEST_IP_O4[RLT_DEST_IP_O4[0][cp_dport] + i] = cp_dip;
					//dip_index4++;
				}else if(D_DEST_IP_O4[RLT_DEST_IP_O4[0][cp_dport] + i] == _DONT_CARE){
					//nothing to do, because oct3 is don't care term
				}else if(D_DEST_IP_O4[RLT_DEST_IP_O4[0][cp_dport] + i] == cp_dip){
					//nothing to do, because it's same path
				}else{
					D_DEST_IP_O4[RLT_DEST_IP_O4[0][cp_dport] + i] = _DONT_CARE;
				}
			}

			RLT_SRC_IP_O1[0][cp_dip] = sip_index0 - dest_ip->ip_min[0];
			RLT_SRC_IP_O2[0][cp_dip] = sip_index1 - dest_ip->ip_min[1];
			RLT_SRC_IP_O3[0][cp_dip] = sip_index2 - dest_ip->ip_min[2];
			RLT_SRC_IP_O4[0][cp_dip] = sip_index3 - dest_ip->ip_min[3];

			RLT_SRC_IP_O1[1][cp_dip] = dest_ip->ip_max[0];
			RLT_SRC_IP_O2[1][cp_dip] = dest_ip->ip_max[1];
			RLT_SRC_IP_O3[1][cp_dip] = dest_ip->ip_max[2];
			RLT_SRC_IP_O4[1][cp_dip] = dest_ip->ip_max[3];

			while(src_ip){
				cp_sip++;
				proto = src_ip->child;

				ip_range(buff_r, src_ip->start, src_ip->stop);

				for(i = buff_r[0]; i <= buff_r[1]; i++){
					if(D_SRC_IP_O1[RLT_SRC_IP_O1[0][cp_dip] + i] == _EMPTY){
						D_SRC_IP_O1[RLT_SRC_IP_O1[0][cp_dip] + i] = cp_sip;
						//sip_index1++;
					}else if(D_SRC_IP_O1[RLT_SRC_IP_O1[0][cp_dip] + i] == _DONT_CARE){
						//nothing to do, because otc1 is don't care term
					}else if(D_SRC_IP_O1[RLT_SRC_IP_O1[0][cp_dip] + i] == cp_sip){
						//nothing to do, because it's same path
					}else{
						D_SRC_IP_O1[RLT_SRC_IP_O1[0][cp_dip] + i] = _DONT_CARE;
					}
				}

				for(i = buff_r[2]; i <= buff_r[3]; i++){
					if(D_SRC_IP_O2[RLT_SRC_IP_O2[0][cp_dip] + i] == _EMPTY){
						D_SRC_IP_O2[RLT_SRC_IP_O2[0][cp_dip] + i] = cp_sip;
						//sip_index2++;
					}else if(D_SRC_IP_O2[RLT_SRC_IP_O2[0][cp_dip] + i] == _DONT_CARE){
						//nothing to do, because oct2 is don't care term
					}else if(D_SRC_IP_O2[RLT_SRC_IP_O2[0][cp_dip] + i] == cp_sip){
						//nothing to do, because it's same path
					}else{
						D_SRC_IP_O2[RLT_SRC_IP_O2[0][cp_dip] + i] = _DONT_CARE;
					}
				}

				for(i = buff_r[4]; i <= buff_r[5]; i++){
					if(D_SRC_IP_O3[RLT_SRC_IP_O3[0][cp_dip] + i] == _EMPTY){
						D_SRC_IP_O3[RLT_SRC_IP_O3[0][cp_dip] + i] = cp_sip;
						//sip_index3++;
					}else if(D_SRC_IP_O3[RLT_SRC_IP_O3[0][cp_dip] + i] == _DONT_CARE){
						//nothing to do, because oct3 is don't care term
					}else if(D_SRC_IP_O3[RLT_SRC_IP_O3[0][cp_dip] + i] == cp_sip){
						//nothing to do, because it's same path
					}else{
						D_SRC_IP_O3[RLT_SRC_IP_O3[0][cp_dip] + i] = _DONT_CARE;
					}
				}

				for(i = buff_r[6]; i <= buff_r[7]; i++){
					if(D_SRC_IP_O4[RLT_SRC_IP_O4[0][cp_dip] + i] == _EMPTY){
						D_SRC_IP_O4[RLT_SRC_IP_O4[0][cp_dip] + i] = cp_sip;
						//sip_index4++;
					}else if(D_SRC_IP_O4[RLT_SRC_IP_O4[0][cp_dip] + i] == _DONT_CARE){
						//nothing to do, because oct3 is don't care term
					}else if(D_SRC_IP_O4[RLT_SRC_IP_O4[0][cp_dip] + i] == cp_sip){
						//nothing to do, because it's same path
					}else{
						D_SRC_IP_O4[RLT_SRC_IP_O4[0][cp_dip] + i] = _DONT_CARE;
					}
				}

				RLT_PROTO[0][cp_sip] = proto_index - src_ip->ip_min[3];
				RLT_PROTO[1][cp_sip] = src_ip->ip_max[3];

				while(proto){
					cp_pro++;
					act = proto->child;

					ip_range(buff_r, proto->start, proto->stop); // buff_r[6 - 7] is for protocol

					for(i = buff_r[6]; i <= buff_r[7]; i++){
						if(D_PROTO[RLT_PROTO[0][cp_sip] + i] == _EMPTY){
							if(act->start == 0 && act->stop == 0){ //for denying an outgoing packet (00)
								D_PROTO[RLT_PROTO[0][cp_sip] + i] = _DENY_OUT;
							}else if (act->start == 0 && act->stop == 1){ //for denying an incoming packet (01)
								D_PROTO[RLT_PROTO[0][cp_sip] + i] = _DENY_IN;
							}else if(act->start == 1 && act->stop == 0){ //for accepting an outgoing packet (10)
								D_PROTO[RLT_PROTO[0][cp_sip] + i] = _ACCEPT_OUT;
							}else if(act->start == 1 && act->stop == 1){ //for accepting an outgoing packet (11)
								D_PROTO[RLT_PROTO[0][cp_sip] + i] = _ACCEPT_IN;
							}else D_PROTO[RLT_PROTO[0][cp_sip] + i] = _EMPTY;
						}
					}

					proto = proto->next;
				}

				count_slot_octx(buff, src_ip->ip_max, src_ip->ip_min);
				proto_index += buff[3];
				//printk("------> proto min = %u,  proto max = %u\n", src_ip->page_min, src_ip->page_max);
				//printk("------> index new page [proto_index] = %ld\n", proto_index);

				src_ip = src_ip->next;
			}

			count_slot_octx(buff, dest_ip->ip_max, dest_ip->ip_min);
			sip_index0 += buff[0];
			sip_index1 += buff[1];
			sip_index2 += buff[2];
			sip_index3 += buff[3];
			//printk("------> index new page [sip_index 1, 2, 3, 4]= %ld, %ld, %ld, %ld\n", sip_index1, sip_index2, sip_index3, sip_index4);

			dest_ip = dest_ip->next;
		}

		count_slot_octx(buff, dest_port->ip_max, dest_port->ip_min);
		dip_index0 += buff[0];
		dip_index1 += buff[1];
		dip_index2 += buff[2];
		dip_index3 += buff[3];
		//printk("------> index new page [dip_index 1, 2, 3, 4]= %ld, %ld, %ld, %ld\n", dip_index0, dip_index1, dip_index2, dip_index3);

		dest_port = dest_port->next;
	}
	//printk("dip_index1 = %ld, dip_index2 = %ld, dip_index3 = %ld, dip_index4 = %ld\n", dip_index0, dip_index1, dip_index2, dip_index3);

	printk(KERN_INFO "FW6: IP packing has finished.\n");
	return 1;
}

void show_IP_packed(){
	int i = 1;

	for(i = 0; i < _MAX_PORT; i++){
		if(DEST_PORT[i] != _EMPTY) printk("DEST_PORT[%d] = %u\n", i, DEST_PORT[i]);
	}

	// RLT for dest_ip
	printk("\n>>> RLT_DEST_IP <<<\n");
	for(i = 0; i < dport_page_size; i++){
		printk("RLT_O1[0][%d]=%ld, RLT_O1[1][%d]=%ld\n", i, RLT_DEST_IP_O1[0][i], i, RLT_DEST_IP_O1[1][i]);
	}
	for(i = 0; i < dport_page_size; i++){
		printk("RLT_02[0][%d]=%ld RLT_O2[1][%d]=%ld\n", i, RLT_DEST_IP_O2[0][i], i, RLT_DEST_IP_O2[1][i]);
	}
	for(i = 0; i < dport_page_size; i++){
		printk("RLT_03[0][%d]=%ld RLT_O3[1][%d]=%ld\n", i, RLT_DEST_IP_O3[0][i], i, RLT_DEST_IP_O3[1][i]);
	}
	for(i = 0; i < dport_page_size; i++){
		printk("RLT_04[0][%d]=%ld RLT_O4[1][%d]=%ld\n", i, RLT_DEST_IP_O4[0][i], i, RLT_DEST_IP_O4[1][i]);
	}

	// 1-D data for dest_ip
	printk("\n>>> D_DEST_IP <<<\n");
	for(i = 0; i < count_slot_dip[0]; i++){
		if(i%9 == 0){
			printk("\n");
		}
		printk(" D1[%d]=%d", i, D_DEST_IP_O1[i]);
	}
	printk("\n");
	for(i = 0; i < count_slot_dip[1]; i++){
		if(i%9 == 0){
			printk("\n");
		}
		printk(" D2[%d]=%d", i, D_DEST_IP_O2[i]);
	}
	printk("\n");
	for(i = 0; i < count_slot_dip[2]; i++){
		if(i%9 == 0){
			printk("\n");
		}
		printk(" D3[%d]=%d", i, D_DEST_IP_O3[i]);
	}
	printk("\n");
	for(i = 0; i < count_slot_dip[3]; i++){
		if(i%9 == 0){
			printk("\n");
		}
		printk(" D4[%d]=%d", i, D_DEST_IP_O4[i]);
	}

 	// RLT for src_ip'
	printk("\n>>> RLT_SRC_IP <<<\n");
	for(i = 0; i < dip_page_size; i++){
		printk("RLT_O1[0][%d]=%ld, RLT_O1[1][%d]=%ld\n", i, RLT_SRC_IP_O1[0][i], i, RLT_SRC_IP_O1[1][i]);
	}
	for(i = 0; i < dip_page_size; i++){
		printk("RLT_02[0][%d]=%ld RLT_O2[1][%d]=%ld\n", i, RLT_SRC_IP_O2[0][i], i, RLT_SRC_IP_O2[1][i]);
	}
	for(i = 0; i < dip_page_size; i++){
		printk("RLT_03[0][%d]=%ld RLT_O3[1][%d]=%ld\n", i, RLT_SRC_IP_O3[0][i], i, RLT_SRC_IP_O3[1][i]);
	}
	for(i = 0; i < dip_page_size; i++){
		printk("RLT_04[0][%d]=%ld RLT_O4[1][%d]=%ld\n", i, RLT_SRC_IP_O4[0][i], i, RLT_SRC_IP_O4[1][i]);
	}

	// D_SRC_IP for src_ip
	printk("\n>>> D_SRC_IP <<<\n");
	for(i = 0; i < count_slot_sip[0]; i++){
		if(i%9 == 0){
			printk("\n");
		}
		printk(" D1[%d]=%d", i, D_SRC_IP_O1[i]);
	}
	printk("\n");
	for(i = 0; i < count_slot_sip[1]; i++){
		if(i%9 == 0){
			printk("\n");
		}
		printk(" D2[%d]=%d", i, D_SRC_IP_O2[i]);
	}
	printk("\n");
	for(i = 0; i < count_slot_sip[2]; i++){
		if(i%9 == 0){
			printk("\n");
		}
		printk(" D3[%d]=%d", i, D_SRC_IP_O3[i]);
	}
	printk("\n");
	for(i = 0; i < count_slot_sip[3]; i++){
		if(i%9 == 0){
			printk("\n");
		}
		printk(" D4[%d]=%d", i, D_SRC_IP_O4[i]);
	}

	//RLT_PROTO
	printk("\n>>> RLT_PROTO <<<\n");
	for(i = 0; i < sip_page_size; i++){
			printk("RLT[0][%d]=%ld RLT[1][%d]=%ld\n", i, RLT_PROTO[0][i], i, RLT_PROTO[1][i]);
		}

	//D_PROTO
	printk(">>> D_PROTO <<<\n");
	for(i = 0; i < count_slot_proto; i++){
		if(i%9 == 0){
			printk("\n");
		}
		printk(" D[%d]=%d", i, D_PROTO[i]);
	}

	return;
}

node *free_FDSD_tree(node *n){
	if(n == NULL) return NULL;
	if(n){
		free_FDSD_tree(n->child);
		free_FDSD_tree(n->next);
		//printk("free %u, %u\n", n->start, n->stop);
		vfree(n);
	}

	return NULL;
}

void activate_packet_filtering(int state){
	FW6_FILTER_ACTIVE = state;
	printk(KERN_INFO "FW6: activated packet filtering (OK).\n");
	printk(KERN_INFO "FW6: ready for filtering IP packet.\n");
}

void packing(void){
	//node *dport_node = root->child;
	//show_FDSD_tree(root->child);
	preprocess_IP_packing(root->child);
	printk("FW6: the number of firewall rules after FDSD processing is %u rules.\n", rule_count);
	IP_PACKING(root->child);
	//preorder_traversal(root);
	//show_IP_packed();

	//set flag to active matching packet in hook-in and hook-out filtering
	//root = free_FDSD_tree(root);
	printk(KERN_INFO "FW6: free FDSD tree (OK).\n");
	activate_packet_filtering(TRUE);

}

/* This function is for packing firewall rules to arrays and packing them for optimizing memory space */
void build_FDSD_tree(void){
	int i, index;
	unsigned int in_out = 0, dport_start = 0, dport_stop = 0;
	unsigned int dip_start = 0, dip_stop = 0, sip_start = 0, sip_stop = 0, pro_start = 0, pro_stop = 0, act = 0;
	printk(KERN_INFO "FW6: build FDSD function has called.\n");
	for(i = 0; i < rule_count; i++){
		index = 0;
		while((sub_rule = strsep(&rules[i], " ")) != NULL){ // split all rules (n rules) from user space to each rule
			if(index == 0){
				in_out = convert_str_to_int(sub_rule);
				index++;
			}else if(index == 1){
				dport_start = convert_str_to_int(sub_rule);
				index++;
			}else if(index == 2){
				dport_stop = convert_str_to_int(sub_rule);
				index++;
			}else if(index == 3){
				dip_start = convert_str_to_int(sub_rule);
				index++;
			}else if(index == 4){
				dip_stop = convert_str_to_int(sub_rule);
				index++;
			}else if(index == 5){
				sip_start = convert_str_to_int(sub_rule);
				index++;
			}else if(index == 6){
				sip_stop = convert_str_to_int(sub_rule);
				index++;
			}else if(index == 7){
				pro_start = convert_str_to_int(sub_rule);
				index++;
			}else if(index == 8){
				pro_stop = convert_str_to_int(sub_rule);
				index++;
			}else if(index == 9){
				act = convert_str_to_int(sub_rule);
				index = 0;
			}
		}

		if(i == 0){ // create the first node and first path in FDSD tree
			root = new_node(0, 0);  //create root node of FDSD tree
			add_child(root, dport_start, dport_stop); // add dest_port to FDSD
			add_child(root, dip_start, dip_stop); // add dest_ip
			add_child(root, sip_start, sip_stop); // add src_ip
			add_child(root, pro_start, pro_stop); // add protocol
			add_child(root, act, in_out); // add action and in/out interface

		}else{ // it's not the first path
			node *tmp_node, *test_node;
			node *dport_node = root->child;
			if((tmp_node = is_member(dport_node, dport_start, dport_stop)) != NULL){
				test_node = tmp_node->child;
				if((tmp_node = is_member(test_node, dip_start, dip_stop)) != NULL){
					test_node = tmp_node->child;
					if((tmp_node = is_member(test_node, sip_start, sip_stop)) != NULL){
						test_node = tmp_node->child;
						if((tmp_node = is_member(test_node, pro_start, pro_stop)) != NULL){
							//same all case, nothing to do
						}else {
							tmp_node = add_sibling(test_node, pro_start, pro_stop);
							add_child(tmp_node, act, in_out);
						}

					}else {
						tmp_node = add_sibling(test_node, sip_start, sip_stop);
						add_child(tmp_node, pro_start, pro_stop);
						add_child(tmp_node, act, in_out);
					}

				}else {
					tmp_node = add_sibling(test_node, dip_start, dip_stop);
					add_child(tmp_node, sip_start, sip_stop);
					add_child(tmp_node, pro_start, pro_stop);
					add_child(tmp_node, act, in_out);
				}

			}else {
				tmp_node = add_sibling(dport_node, dport_start, dport_stop);
				add_child(tmp_node, dip_start, dip_stop);
				add_child(tmp_node, sip_start, sip_stop);
				add_child(tmp_node, pro_start, pro_stop);
				add_child(tmp_node, act, in_out);
			}

		}
	}

	printk(KERN_INFO "FW6: build FDSD firewall rules before packing (OK).\n");
	vfree(rules);
	return;
}


/* This function is called with the /proc file is written from user such as echo "hello" > /proc/FW6
 * default maximum buffer size of procf_write is 1024 KB for writing to buffer at a time
 * */
int procf_write(struct file *filp, const char *buffer, unsigned long count, void *data){

	unsigned short i, j;

	if(_DEBUG) printk(KERN_INFO "FW6: procf_write has called.\n");
	if(_DEBUG) printk(KERN_INFO "FW6: count = %lu\n", count);
	/* get buffer size */
	if(count > _PROCFS_MAX_SIZE){
		procfs_buffer_size = _PROCFS_MAX_SIZE;
	}else{
		procfs_buffer_size = count;
	}

	/* write data to the buffer */
	procfs_buffer = vmalloc(procfs_buffer_size * sizeof (char *));

	if(copy_from_user(procfs_buffer, buffer, procfs_buffer_size)){
		if(_DEBUG) printk(KERN_INFO "FW6: cannot write file.\n");
		if(_DEBUG) printk(KERN_INFO "FW6: buffer = %s\n", buffer);
		if(_DEBUG) printk(KERN_INFO "FW6: procfs buffer = %s\n", procfs_buffer);
		return -EFAULT;
	}

	count_buff += procfs_buffer_size;
	if(_DEBUG) printk(KERN_INFO "FW6: procfs wrote %lu bytes\n", procfs_buffer_size);
	//printk(KERN_INFO "FW6: test print data %d \n", procfs_buffer[3]);


	if(count_buff > _PROCFS_MAX_SIZE){
		printk(KERN_INFO "FW6: buffer is overflow, needs to resizing _PROCFS_MAX_SIZE.\n");
		return -EFAULT;
	}

	i = 0;

	while(procfs_buffer[i]){
		if(procfs_buffer[i] != _EOF){
			procfs_buffer_fw[procfs_buffer_index] = procfs_buffer[i];
			procfs_buffer_index++;
			if(procfs_buffer[i] == '\n'){
				rule_count_tmp++;
			}
			i++;
		}else{
			FW6_WRITE_OK = TRUE;
			break;
		}
	}

	vfree(procfs_buffer);

	if(FW6_WRITE_OK){

		printk(KERN_INFO "FW6: procfs wrote %lu bytes\n", count_buff);
		printk(KERN_INFO "FW6: the number of firewall rules before FDSD processing is %u rules\n", rule_count_tmp);

		if(rule_count_tmp > _MAX_RULES){ // check whether the number of rules are not over defined _MAX_RULES
			printk(KERN_INFO "FW6: the rule of high speed firewall is over %u\n", _MAX_RULES);
			return -ENOSPC;
		}

		rules = (char**)vmalloc(rule_count_tmp * sizeof (char *));

		j = 0; i = 1;
		while((sub_rule = strsep(&procfs_buffer_fw, "\n")) != NULL){ // split all rules (n rules) from user space to each rule
			if(i > rule_count_tmp) break;
			rules[j] = sub_rule;
			//printk("---> %s\n", rules[j]);
			j++;
			i++;
		}

		vfree(procfs_buffer_fw);
		rule_count = rule_count_tmp;
		FW6_init_misc();
		FW6_WRITE_OK = FALSE;
		activate_packet_filtering(FALSE);
		build_FDSD_tree();
		packing();
	}

	return procfs_buffer_size;
}

/* This function is called then the /proc file is read (read from user such as cat /proc/FW6)*/
int procf_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data){
	int ret;
	printk(KERN_INFO "FW6: procfile_read (/proc/%s) has called\n", _PROCF_NAME);
	if (offset > 0){
		/* we have finished to read, return 0 */
		ret  = 0;
	}else {
		/* fill the buffer, return the buffer size */
		ret = sprintf(buffer, "Welcome to High Speed Linux Firewall (FW6)!\n");
	}

	return ret;
}

int init_read_write_module(void) {
	int ret = 0;
	procfs_buffer = (char *) vmalloc(_PROCFS_MAX_SIZE);
	procf_entry = create_proc_entry(_PROCF_NAME, _PERMISSION, NULL); //create proc file to interact between user and kernel module
	if (procf_entry == NULL) {
		printk(KERN_INFO "FW6: /proc/%s could not be created.\n", _PROCF_NAME);
		ret = -1;
		vfree(procfs_buffer);
		return -ENOMEM;
	}else{
		printk(KERN_INFO "FW6: /proc/%s has created (OK).\n", _PROCF_NAME);
		procf_entry->read_proc = procf_read;
		procf_entry->write_proc = procf_write;
		rule_count = 0;
		rule_count_tmp = 0;
		printk(KERN_INFO "FW6: initialized read and write function (OK).\n");
	}

	return ret;
}

int matching_packet(struct sk_buff *skb){
	unsigned short src_ip_byte[4];
	unsigned short dest_ip_byte[4];
	unsigned int src_ip;
	unsigned int dest_ip;
	unsigned int src_port;
	unsigned int dest_port;
	unsigned short proto;
	int page;

	// initializing the IP packet's headers which are inside a union in sk_buff structure
	//struct ethhdr *eth_h 	=	eth_hdr(skb);
	struct iphdr *ip_header 	= 	ipip_hdr(skb);		// defined in /lib.../linux/ip.h, returns iphdr as (struct iphdr*)skb_network_header(skb)
	struct tcphdr *tcp_header 	=	tcp_hdr(skb);		// in /lib.../tcp.h, 	returns tcphdr as (struct tcphdr*)skb_transport_header(skb)
	struct udphdr *udp_header 	=	udp_hdr(skb);		// in /lib.../udp.h, 	returns udphdr as (struct udphdr*)skb_transport_header(skb)
	//struct icmphdr *icmp_header =	icmp_hdr(skb);		// in /lib/.../icmp.h, 	returns icmphdr as (struct icmphdr*)skb_transport_header(skb)
	//printk(KERN_DEBUG "%pI4", ip_header->saddr);

	 // don't want any NULL pointers in the chain to the skb, IP, TCP and UDP header.
	  if (!skb) return NF_ACCEPT;

	  // get src and dest ip addresses
	  src_ip = (unsigned int)ip_header->saddr;	//this SRC_IP is reversed order
	  dest_ip = (unsigned int)ip_header->daddr; //DEST_IP also is reversed order

	  int_to_IP_byte_array(src_ip_byte, src_ip);
	  //printk("SRC IP bytes = [%u], [%u], [%u], [%u]\n", src_ip_byte[3], src_ip_byte[2], src_ip_byte[1], src_ip_byte[0]);
	  int_to_IP_byte_array(dest_ip_byte, dest_ip);
	  //printk("DEST IP bytes = [%u], [%u], [%u], [%u]\n", dest_ip_byte[3], dest_ip_byte[2], dest_ip_byte[1], dest_ip_byte[0]);

	  // get src and dest port number
	  src_port = 0;
	  dest_port = 0;

	  //printk(KERN_INFO "%pI4\n", &(ip_header->saddr));
	  //printk(KERN_INFO "src_ip = %d.%d.%d.%d\n", (ip_header->saddr) & 255, (ip_header->saddr >> 8U) & 255, (ip_header->saddr >> 16U) & 255, (ip_header->saddr >> 24U) & 255);
	  //printk("PROTOCOL = %u\n", ip_header->protocol);

	  proto = ip_header->protocol;

	  if (proto == _TCP){
		  dest_port = tcp_header->dest;
	  }else if(proto == _UDP){
		  dest_port = udp_header->dest;
	  }


/***********************************************************************
 *          MATCHING PACKET AGAINST FW6 STRUCTURES                  *
 ***********************************************************************/

	  if(FW6_FILTER_ACTIVE){
		  //printk("filtering\n");
		  page = DEST_PORT[dest_port];
		  if(page < _EMPTY || page >= _MAX_PORT){
			  return _NO_MATCH;
		  }else{
			  // DEST_IP matching
			  if((RLT_DEST_IP_O1[0][page] + dest_ip_byte[3]) < 0 || RLT_DEST_IP_O1[1][page] < dest_ip_byte[3] || (RLT_DEST_IP_O2[0][page] + dest_ip_byte[2]) < 0 || RLT_DEST_IP_O2[1][page] < dest_ip_byte[2] || (RLT_DEST_IP_O3[0][page] + dest_ip_byte[1]) < 0 || RLT_DEST_IP_O3[1][page] < dest_ip_byte[1] || (RLT_DEST_IP_O4[0][page] + dest_ip_byte[0]) < 0 || RLT_DEST_IP_O4[1][page] < dest_ip_byte[0]){
				  return _NO_MATCH;
			  }
			  if(D_DEST_IP_O1[RLT_DEST_IP_O1[0][page] + dest_ip_byte[3]] == _EMPTY || D_DEST_IP_O2[RLT_DEST_IP_O2[0][page] + dest_ip_byte[2]] == _EMPTY || D_DEST_IP_O3[RLT_DEST_IP_O3[0][page] + dest_ip_byte[1]] == _EMPTY || D_DEST_IP_O4[RLT_DEST_IP_O4[0][page] + dest_ip_byte[0]] == _EMPTY){
				  return _NO_MATCH;
			  }else{
				  if(D_DEST_IP_O1[RLT_DEST_IP_O1[0][page] + dest_ip_byte[3]] != _DONT_CARE){
					  page = D_DEST_IP_O1[RLT_DEST_IP_O1[0][page] + dest_ip_byte[3]];
				  }else if(D_DEST_IP_O2[RLT_DEST_IP_O2[0][page] + dest_ip_byte[2]] != _DONT_CARE){
					  page = D_DEST_IP_O2[RLT_DEST_IP_O2[0][page] + dest_ip_byte[2]];
				  }else if(D_DEST_IP_O3[RLT_DEST_IP_O3[0][page] + dest_ip_byte[1]] != _DONT_CARE){
					  page = D_DEST_IP_O3[RLT_DEST_IP_O3[0][page] + dest_ip_byte[1]];
				  }else if(D_DEST_IP_O4[RLT_DEST_IP_O4[0][page] + dest_ip_byte[0]] != _DONT_CARE){
					  page = D_DEST_IP_O4[RLT_DEST_IP_O4[0][page] + dest_ip_byte[0]];
				  }else {return _NO_MATCH;}

				  //SRC_IP matching
				  if((RLT_SRC_IP_O1[0][page] + src_ip_byte[3] < 0) || RLT_SRC_IP_O1[1][page] < src_ip_byte[3] || (RLT_SRC_IP_O2[0][page] + src_ip_byte[2]) < 0 || RLT_SRC_IP_O2[1][page] < src_ip_byte[2] || (RLT_SRC_IP_O3[0][page] + src_ip_byte[1]) < 0 || RLT_SRC_IP_O3[1][page] < src_ip_byte[1] || (RLT_SRC_IP_O4[0][page] + src_ip_byte[0]) < 0 || RLT_SRC_IP_O4[1][page] < src_ip_byte[0]){

					  return _NO_MATCH;
				  }
				  if(D_SRC_IP_O1[RLT_SRC_IP_O1[0][page] + src_ip_byte[3]] == _EMPTY || D_SRC_IP_O2[RLT_SRC_IP_O2[0][page] + src_ip_byte[2]] == _EMPTY || D_SRC_IP_O3[RLT_SRC_IP_O3[0][page] + src_ip_byte[1]] == _EMPTY || D_SRC_IP_O4[RLT_SRC_IP_O4[0][page] + src_ip_byte[0]] == _EMPTY){
					  return _NO_MATCH;
				  }else{
					  if(D_SRC_IP_O4[RLT_SRC_IP_O4[0][page] + src_ip_byte[0]] != _DONT_CARE){
						  page = D_SRC_IP_O4[RLT_SRC_IP_O4[0][page] + src_ip_byte[0]];
					  }else if(D_SRC_IP_O3[RLT_SRC_IP_O3[0][page] + src_ip_byte[1]] != _DONT_CARE){
						  page = D_SRC_IP_O3[RLT_SRC_IP_O3[0][page] + src_ip_byte[1]];
					  }else if(D_SRC_IP_O2[RLT_SRC_IP_O2[0][page] + src_ip_byte[2]] != _DONT_CARE){
						  page = D_SRC_IP_O2[RLT_SRC_IP_O2[0][page] + src_ip_byte[2]];
					  }else if(D_SRC_IP_O1[RLT_SRC_IP_O1[0][page] + src_ip_byte[3]] != _DONT_CARE){
						  page = D_SRC_IP_O1[RLT_SRC_IP_O1[0][page] + src_ip_byte[3]];
					  }else {return _NO_MATCH;}
				  }

				  //PROTO matching
				  if((RLT_PROTO[0][page] + proto) < 0 || RLT_PROTO[1][page] < proto){
					  return _NO_MATCH;
				  }
				  if(D_PROTO[RLT_PROTO[0][page] + proto] == _EMPTY){
					  return _NO_MATCH;
				  }else{
					  //printk("MATCH = %u, proto = %u\n", D_PROTO[RLT_PROTO[page] + proto], proto);
					  return D_PROTO[RLT_PROTO[0][page] + proto];
				  }
			  }
		  }
	  }

	  return _MATCH;
}

unsigned int FW6_inbound_filter(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	int action;
	//printk("FW6: FW6_inbound_filter\n");
	action = matching_packet(skb);
	if(action == _NO_MATCH){
		//printk("FW6: no any inbound packet matches\n");
		return NF_ACCEPT;
	}else if(action == _DENY_IN){ //_DENY_IN
		//printk("FW6: inbound packet dropped\n");
		return NF_DROP;
	}else if(action == _ACCEPT_IN){ //_ACCEPT_IN
		//printk("FW6: inbound packet passed\n");
		return NF_ACCEPT;
	}

	return NF_ACCEPT;
}

unsigned int FW6_outbound_filter(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	int action;
	//printk("FW6: FW6_outbound_filter\n");
	action = matching_packet(skb);
	if(action == _NO_MATCH){
		//printk("FW6: no any outbound packet matches\n");
		return NF_ACCEPT;
	}else if(action == _DENY_OUT){ //_DENY_OUT
		//printk("FW6: outbound packet dropped\n");
		return NF_DROP;
	}else if(action == _ACCEPT_OUT){ //_ACCEPT_OUT
		//printk("FW6: outbound packet passed\n");
		return NF_ACCEPT;
	}

	return NF_ACCEPT;
}

void FW6_init_misc(){
	//initialize memory for storing all rules
	procfs_buffer_fw = vmalloc(_PROCFS_MAX_SIZE * sizeof (char *));
	memset(procfs_buffer_fw, _EMPTY, _PROCFS_MAX_SIZE);
	procfs_buffer_index = 0;
	rule_count_tmp = 0;
	count_buff = 0;
	return;
}

void FW6_cleanup_misc(){
	//cleanup memory
	vfree(procfs_buffer_fw);
	return;
}

void cleanup_read_write_module(void) {
	remove_proc_entry(_PROCF_NAME, NULL);
	printk(KERN_INFO "FW6: /proc/%s has removed\n", _PROCF_NAME);
	printk(KERN_INFO "FW6: cleaned up read and write module function (OK).\n");
	return;
}

int init_hook_module(void) {
	nfho_in.hook		= FW6_inbound_filter;		// filter for inbound packets
	nfho_in.hooknum 	= NF_INET_LOCAL_IN;				// netfilter hook for local machine bounded ipv4 packets
	nfho_in.pf			= PF_INET;
	nfho_in.priority 	= NF_IP_PRI_FIRST;				// we set its priority higher than other hooks
	nf_register_hook(&nfho_in);

	nfho_out.hook		= FW6_outbound_filter;		// filter for outbound packets
	nfho_out.hooknum	= NF_INET_LOCAL_OUT;
	nfho_out.pf			= PF_INET;
	nfho_out.priority	= NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_out);

	printk(KERN_INFO "FW6: registering hook module (OK).\n");
	return 0;
}

void cleanup_hook_module(void) {
	nf_unregister_hook(&nfho_in);
	nf_unregister_hook(&nfho_out);
	printk(KERN_INFO "FW6: unregistering hook module (OK).\n");
	return;
}

/************************** main module *************************************************
 *																						*
 * init_module is called when high speed linux firewall loaded by insmod command	    *
 * cleanup_module is called when high speed linux firewall unloaded by rmmod command	*
 *  																					*
 ****************************************************************************************/
int FW6_init_module(void) {
	printk(KERN_INFO "FW6: ***********************************************************\n");
	printk(KERN_INFO "FW6: *            High Speed Linux Firewall (FW6)            *\n");
	printk(KERN_INFO "FW6: ***********************************************************\n");
	FW6_init_misc();
	init_read_write_module();
	init_hook_module();
	printk(KERN_INFO "FW6: high speed linux kernel module loaded and started successfully.\n");
	return 0;
}

void FW6_cleanup_module(void) {
	cleanup_read_write_module();
	cleanup_hook_module();
	FW6_cleanup_misc();
	printk(KERN_INFO "FW6: high speed linux kernel module unloaded and stoped successfully.\n");
	return;
}

module_init(FW6_init_module);
module_exit(FW6_cleanup_module);


