/*
 * FW6.c
 *
 *  Created on: Oct 15, 2016
 *      Author: root
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>

/* these header files contain Internet packets and miscellaneous */
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>

#include "FW6.h"

#define FLAG_SET	0
#define test_in_out(x) (x ==_OUT? _OUT : _IN)
#define print(x) (x == 0? "out" : "in")
#define get_in_out(x) (strcmp(x, "in")? _OUT : _IN)

/* shortopts structure for getopt_long() function in getopt.h */
// ':' shows that its argument is required, null ('\0') character for not.
char short_opts[] = {	_PROTO,    	':',
		    			_SRC_IP,  	':',
		    			_DST_IP,  	':',
		    			_SRC_PORT, 	':',
		    			_DEST_PORT, ':',
		    			_SRC_MASK, 	':',
		    			_DEST_MASK, ':',
		    			_ACT,       ':',
		    			_DEL,		':',
		    			_APPLY,		':',
		    			_PRINT,   	'\0',
						_HELP,   	'\0',
						_QUEST,		'\0'
		    		};

int in_out_flag = -1;	// to check whether packet in or pack out
static unsigned int rule_count;	//to count normal firewall rules

/* Declare function of firewall header prototypes */
void init_fw(void);
char *lowercase(const char *argv);
unsigned char valid_digit(char *ip_str);
unsigned char validate_ip_or_mask(const char *optarg);
unsigned char validate_port(const char *optarg);
void set_x(const char *optarg, unsigned char type);
void del_fw_rule(const char *optarg);
void set_hook(unsigned char hook_id);
void write_to_procf(node *);
void read_from_procf(unsigned char struct_id);
void write_fw_rule(unsigned char rule_type);
void print_fw_rule(void);
char *format_fw_rule(void);
void apply(void);
void open_help(void);
stack *init_stack();
void push(stack *s, data dx);
data pop(stack *s);
void show_stack(stack *s);
int stack_is_empty(stack *s);
int stack_is_full(stack *s);
data stack_peek(stack *s);
int stack_size(stack *s);
lst_node dequeue(queue *q);
int enqueue(queue *q, lst_node lst);
int queue_is_full(queue *q);
int queue_is_empty(queue *q);
lst_node queue_peek(queue *q);
int queue_size(queue *q);
queue *init_queue();
void reset_queue(queue *q);
void show_queue(queue *q);
dsd_struct *preprocess_FDSD(void);
int split(char *str, const char *delim, char ***array, int *length);
unsigned int convert_IP_to_int(char *ipadr);
char *convert_int_to_IP(unsigned int long_ip);
unsigned int convert_port_to_int(char *any_port);
unsigned char convert_proto_to_int(char *any_proto);
unsigned int count_bit_subnetmask(char *subnetmask);
char *my_ntoa(unsigned int ip);
void calculate_IP_addresses(char *ip, char *ip_netmask);
unsigned int count_rule_in_file(void);
char *trim_newline(char *str);
node *new_node(unsigned int start, unsigned int stop);
node *add_child(node *n, unsigned int start, unsigned int stop);
node *add_sibling(node *n, unsigned int start, unsigned int stop);
void preorder_traversal(node *n);
void subtract(unsigned int A_start, unsigned int  A_stop, unsigned int B_start, unsigned int B_stop);
void show_iptables(dsd_struct *iptables);
void create_FDSD_tree(node *n, dsd_struct rule_x);
node *FDSD(dsd_struct *iptables);
node *free_FDSD_tree(node *n);

/************************************************************************************************
 * 																								*
 *                         Main program of FW6 linux High speed Firewall                      *
 *                               																*
 ************************************************************************************************/
int main(int argc, char **argv) {

	int opt;
	init_fw();

	while(1) {

		// long_opts consisting of {char *name, int has_arg, int *flag, int val}
		static struct option long_opts[] =
				{
					{"out",			no_argument,		&in_out_flag, 0},
					{"in",			no_argument,		&in_out_flag, 1},
					{"proto",		required_argument,	0,  _PROTO},
					{"srcip",		required_argument,	0, 	_SRC_IP},
					{"destip",		required_argument, 	0,  _DST_IP},
					{"srcport",		required_argument, 	0, 	_SRC_PORT},
					{"destport",    required_argument, 	0, 	_DEST_PORT},
					{"srcnetmask",	required_argument, 	0, 	_SRC_MASK},
					{"destnetmask",	required_argument, 	0, 	_DEST_MASK},
					{"action",		required_argument, 	0, 	_ACT},
					{"delete",		required_argument,	0, 	_DEL},
					{"print",		no_argument,		0,  _PRINT},
					{"apply",		no_argument,		0,  _APPLY},
					{"help",		no_argument,		0,  _HELP},
					{"?",			no_argument,		0,  _QUEST},
					{0, 0, 0, 0}
				};

		/* call getopt_long function in getotp.h (int getopt_long(int argc, char *argv, char *shortopt, option *long_opts, int indexptr)
		 *
		 * */
		int index_ptr = 0;
		opt = getopt_long(argc, argv, short_opts, long_opts, &index_ptr);

		/* detect the end of the options. */
		if(opt == -1) break;

		switch(opt) {
			case FLAG_SET:
				if(long_opts[index_ptr].flag != 0){		// means that the in_out_flag has been set, and optarg will be NULL
					if(_DEBUG) printf ("option = %d\n", opt);
					if(_DEBUG) printf("case: packet (out = 0, in = 1) = %d\n", test_in_out(in_out_flag));
					if(test_in_out(in_out_flag) == _OUT){
						if(_DEBUG) printf("packet out = %d\n",_OUT);
						firewall_rule.in_out = _OUT;
						contr_cmd.id = _ADD;
						contr_cmd.name = (char *)long_opts[index_ptr].name;
						if(_DEBUG) printf("contr_cmd = %u, %s\n",(unsigned char)contr_cmd.id, contr_cmd.name);
					}else if(test_in_out(in_out_flag) == _IN){
						if(_DEBUG) printf("packet in = %d\n",_IN);
						firewall_rule.in_out = _IN;
						contr_cmd.id = _ADD;
						contr_cmd.name = (char *)long_opts[index_ptr].name;
						if(_DEBUG) printf("contr_cmd = %u, %s\n",(unsigned char)contr_cmd.id, contr_cmd.name);
					}
					break;
				}
				/*printf ("option %s\n", long_opts[index_ptr].name);
				if(optarg)
				printf (" with arg %s", optarg);
				printf ("\n"); */
				break;

			case _SRC_IP:
				if(_DEBUG) printf ("case: src ip with arg = %s\n", optarg);
				set_x(optarg, _IS_SRC_IP); // type (0) = src ip
				break;

			case _DST_IP:
				if(_DEBUG) printf ("case: dst ip with arg = %s\n", optarg);
				set_x(optarg, _IS_DEST_IP); // type (4) = dest ip
				break;

			case _SRC_MASK:
				if(_DEBUG) printf ("case: src mask with arg = %s\n", optarg);
				set_x(optarg, _IS_SRC_MASK); // type (1) = src ip mask
				break;

			case _DEST_MASK:
				if(_DEBUG) printf ("case: dst mask with arg = %s\n", optarg);
				set_x(optarg, _IS_DEST_MASK); // type (5) = dest ip mask
				break;

			case _SRC_PORT:
				if(_DEBUG) printf ("case: src port with arg = %s\n", optarg);
				set_x(optarg, _IS_SRC_PORT); // type (3) = src port
				break;

			case _DEST_PORT:
				if(_DEBUG) printf ("case: dst port with arg = %s\n", optarg);
				set_x(optarg, _IS_DEST_PORT); // type (6) = dest port
				break;

			case _PROTO:
				if(_DEBUG) printf ("case: protocol with arg = %s\n", optarg);
				set_x(optarg, _IS_PROTO); // type (7) = protocol
				break;

			case _ACT:
				if(_DEBUG) printf ("case: action with arg = %s\n", optarg);
				set_x(optarg, _IS_ACT); // type (8) = action
				break;

			case _DEL:
				if(_DEBUG) printf ("case: delete with arg = %s\n", optarg);
				contr_cmd.id = _DEL;
				contr_cmd.name = (char *)long_opts[index_ptr].name;
				contr_cmd.no = optarg;
				if(_DEBUG) printf("contr_cmd (id, name, rule_no) = %u, %s, %s\n",(unsigned char)contr_cmd.id, contr_cmd.name, contr_cmd.no);
				del_fw_rule(optarg);
				exit(EXIT_SUCCESS);

			case _PRINT:
				if(_DEBUG) printf ("case: print \n");
				print_fw_rule();
				exit(EXIT_SUCCESS);

			case _APPLY:
				if(_DEBUG) printf ("case: apply \n");
				contr_cmd.id = _APPLY;
				contr_cmd.name = (char *)long_opts[index_ptr].name;
				contr_cmd.no = optarg;
				apply();
				printf("Apply completed.\n");
				exit(EXIT_SUCCESS);

			case _HELP:
			case _QUEST:
				if(_DEBUG) printf ("case: help \n");
				open_help();
				exit(EXIT_SUCCESS);

			default: exit(EXIT_FAILURE); // abort();

		}
	}

	if(in_out_flag == 0) {	// set hook type to firewall_rule for filtering out-coming packet
		if(_DEBUG) printf("out-bound packet incoming\n");
		set_hook(_OUT);
	}else if(in_out_flag == 1) { // set hook type to firewall_rule for filtering in-going packet
		if(_DEBUG) printf("in-bound packet incoming\n");
		set_hook(_IN);
	}

	//printf("optind = %d\n", optind);
	if(optind < argc) {
			printf("Non-option arguments: ");
			while(optind < argc)
				printf("%s ", argv[optind++]);
			putchar('\n');
		}else{
			//write to firewall rule in plain text (firewall_rule.pt)
			write_fw_rule(_NOR_FW_RULE);
			//read_from_procf(_FW_STRUCT);
		}

	return 0;
}

/*********************************** END OF Main FW6 firewall ***************************************/

void show_queue(queue *q){
	int i;
	if(q->itemCount == 0){
		printf ("show_queue: queue is empty\n");
		return;
	}else{
		printf("show_queue: the data in queue are: \n");
		for(i = q->front; i <= q->rear; i++){
			printf ("show_queue: (%u, %d)\n", q->item[i].case_no, q->item[i].addr);
		}
	}
	return;
}

lst_node dequeue(queue *q){
	lst_node lst;
	if(queue_is_empty(q)){
		printf("dequeue: queue is empty\n");
		lst.case_no = _NO_CASE; lst.addr = NULL;
		reset_queue(q);
		return lst;
	}
	if(q->front == _QUEUE_MAX) {
		q->front = 0;
	}
	lst = q->item[q->front];
	q->front++;
	q->itemCount--;
	if(_DEBUG) printf("dequeue: font, rear, itemCount-----> %d, %d, %d\n", q->front, q->rear, q->itemCount);
	return lst;
}

int enqueue(queue *q, lst_node lst) {
	if(queue_is_full(q)){
		printf("enqueue: queue is full\n");
		return 0;
	}
	if(q->rear == (_QUEUE_MAX - 1)){
		q->rear = -1;
	}
	q->rear++;
	q->item[q->rear] = lst;
	q->itemCount++;
	if(_DEBUG) printf("enqueue: font, rear, itemCount-----> %d, %d, %d\n", q->front, q->rear, q->itemCount);
	return 1;
}

int queue_is_full(queue *q){
	if(q->rear == (_QUEUE_MAX - 1))//if(q->itemCount == _QUEUE_MAX)
		return 1;
	else
		return 0;
}

int queue_is_empty(queue *q){
	if(q->front < 0 || q->front > q->rear) //if(q->itemCount == 0)
		return 1;
	else
		return 0;
}

lst_node queue_peek(queue *q){
	return q->item[q->front];
}

int queue_size(queue *q){
	if(_DEBUG) printf("queue size = %d\n", q->itemCount);
	return q->itemCount;
}

queue *init_queue(){
	struct queue *q = (queue*)malloc(sizeof (queue));
	q->front = 0;
	q->rear = -1;
	q->itemCount = 0;
	return q;
}

void reset_queue(queue *q){
	q->front = 0;
	q->rear = -1;
	q->itemCount = 0;
	return;
}

int stack_is_empty(stack *s){
	if(s->top == -1)
		return 1;
	else
		return 0;
}

int stack_is_full(stack *s){
	if(s->top == (_STACK_MAX - 1))
		return 1;
	else
		return 0;
}

data stack_peek(stack *s){
	return s->item[s->top];
}

int stack_size(stack *s){
	if(_DEBUG) printf("stack size = %d\n", (s->top + 1));
	return (s->top + 1);
}

stack *init_stack(){
	struct stack *s = (stack*)malloc(sizeof (stack));
	s->top = -1;
	return s;
}

void push(stack *s, data dx){

	if(stack_is_full(s)){
		 printf("push: stack is full\n");
		 return;
	}else{
		s->top++; // = s->top + 1;
		s->item[s->top] = dx;
	}
	return;
}

data pop(stack *s){
	data dx;
	if(stack_is_empty(s)){
		printf("pop: stack is empty\n");
		dx.start = 0; dx.stop = 0;
		return dx;
	}else{
		dx = s->item[s->top];
		if(_DEBUG) printf("pop: poped element is = (%u, %u)\n", s->item[s->top].start, s->item[s->top].stop);
		s->top--; //= s->top - 1;
	}
	return dx;
}

void show_stack(stack *s){
	int i;
	if(s->top == -1){
		printf ("show_stack: stack is empty\n");
		return;
	}else{
		printf("show_stack: the data in stack are: \n");
		for(i = s->top; i >= 0; i--){
			printf ("show_stack: (%u, %u)\n", s->item[i].start, s->item[i].stop);
		}
	}
	return;
}

void preorder_traversal(node *n){
	if(n == NULL) {
		//printf("---------------------------------------------\n");
		return;
	}
	printf("%u, %u\n",n->start, n->stop);
	preorder_traversal(n->child);

	preorder_traversal(n->next);
}

node *new_node(unsigned int start, unsigned int stop){
	node *new_node = malloc(sizeof(node));
	if(new_node) {
		new_node->next = NULL;
	    new_node->child = NULL;
	    new_node->start = start;
	    new_node->stop = stop;
	}
	return new_node;
}

node *add_sibling(node *n, unsigned int start, unsigned int stop){
	if(n == NULL)
		return NULL;

	while (n->next)
		n = n->next;

	return (n->next = new_node(start, stop));
}

node *add_child(node *n, unsigned int start, unsigned int stop){
	if(n == NULL)
		return NULL;

	while (n->child)
		n = n->child;

	return (n->child = new_node(start, stop));
//	 if (n->child)
//		 return add_sibling(n->child, start, stop);
//	 else
//		 return (n->child = new_node(start, stop));
}

void subtract(unsigned int A_start, unsigned int  A_stop, unsigned int B_start, unsigned int B_stop){
	/******************************************************************************************************
	 * case 0: A is disjoint B
	 * A		1------3					,		   6---------10
	 * B				  5-------------10	, 1-----4
	 *******************************************************************************************************
	 * case 1: A is completely super set of B
	 * A		1------------------------10	, 1------------------10, 2---------------8	, 2---------------8
	 * B	         4----------6			, 1------------------10, 2-------5			,          5------8
	 *******************************************************************************************************
	 * case 2: A is completely sub set of B, 			 A is some sub set of B
	 * A		    4------7				, 1-------3				, 		6--------10
	 * B		1------------------------10	, 1----------------7	, 1--------------10
	 * return	|---|		|------------|	, 		  |--------|	, |-----|
	 * 			          2(1)		    					      2(2)
	 * *****************************************************************************************************
	 * case 3: A is intersect B
	 * A			3---------------8,    3----------8	, 1--------------5		, 1--------5
	 * B		1------------5		 , 1--3				,        3-----------7	,          5--------8
	 * return	|---|		 |------|, |--||---------|	, |------|		  |--|
	 *			                    3(1)		  		3(2)
	 *******************************************************************************************************/
	//case 0: --> set case_no = 0 (disjoint), no get data
	if(A_stop < B_start || A_start > B_stop){
		//return B_start and B_stop
		sub_result.case_no = _DISJOINT;
		if(A_stop < B_start){
			sub_result.start1 = B_start;
			sub_result.stop1 = B_stop;
		}else{
			sub_result.start1 = B_start;
			sub_result.stop1 = B_stop;
		}
		if(_DEBUG) printf("subtract: case 0: A is disjoint B (result = 0 set)\n");

	}else if(A_start <= B_start && A_stop >= B_stop){ //case 1: --> no get data
		//return case, and don't anythings
		sub_result.case_no = _COMP_SUPERSET;
		if(_DEBUG)	printf("subtract: case 1: A is super set B (result = 0 set)\n");

	}else if(A_start > B_start && A_stop < B_stop){ //case 2(1):--> get data from start1, stop1, start2 and stop2
		//return (B_start, A_start - 1), (A_stop + 1, B_stop)
		sub_result.case_no = _COMP_SUBSET;
		sub_result.start1 = B_start;
		sub_result.stop1 = A_start - 1;
		sub_result.start2 = A_stop + 1;
		sub_result.stop2 = B_stop;
		if(_DEBUG)	printf("subtract: case 2(1): A is completely subset B (result = 2 set)\n");

	}else if(A_start == B_start && A_stop < B_stop){ //case 2(2):--> get data from start1 and stop1
		//return (A_stop + 1, B_stop)
		sub_result.case_no = _SOME_SUBSET;
		sub_result.start1 = A_stop + 1;
		sub_result.stop1 = B_stop;
		if(_DEBUG)	printf("subtract: case 2(2): A is subset B (left) (result = 1 set)\n");

	}else if(A_start > B_start && A_stop == B_stop){ //case 2(3):--> get data from start1 and stop1
		//return (B_start, A_start - 1)
		sub_result.case_no = _SOME_SUBSET;
		sub_result.start1 = B_start;
		sub_result.stop1 = A_start - 1;
		if(_DEBUG)	printf("subtract: case 2(3): A is subset B (right) (result = 1 set)\n");

	}else if(A_start <= B_stop && A_stop > B_stop){ //case 3(1):--> get data from start1, stop1, start2 and stop2
		//return (B_start, A_start - 1)
		sub_result.case_no = _INTESECTION;
		sub_result.start1 = B_start;
		sub_result.stop1 = A_start - 1;
		sub_result.start2 = B_stop + 1;
		sub_result.stop2 = A_stop;
		if(_DEBUG)	printf("subtract: case 3(1): A is intersect B (result = 2 set)\n");

	}else if(A_start < B_start && A_stop >= B_start){ //case 3(2):--> get data from start1, stop1, start2 and stop2
		//return (A_stop + 1, B_stop)
		sub_result.case_no = _INTESECTION;
		sub_result.start1 = A_start;
		sub_result.stop1 = B_start - 1;
		sub_result.start2 = A_stop + 1;
		sub_result.stop2 = B_stop;
		if(_DEBUG)	printf("subtract: case 3(2): A is intersect B (result = 2 set)\n");
	}else {
		sub_result.case_no = _NO_CASE;
		if(_DEBUG)	printf("subtract: NOT MATCH\n");
	}
	return;
}

void show_subtract(){
	if(sub_result.case_no == _DISJOINT){
		//if(_DEBUG)
			printf("show_subtract: case 0 (disjoint) = (%u, %u)\n", sub_result.start1, sub_result.stop1);
	}else if(sub_result.case_no == _COMP_SUPERSET){
		//if(_DEBUG)
		printf("show_subtract: case 1 (A is completely super set of B)\n");
	}else if(sub_result.case_no == _SOME_SUBSET){
		//if(_DEBUG)
		printf("show_subtract: case 2(2), 2(3) (A is some sub set of B) = (%u, %u)\n", sub_result.start1, sub_result.stop1);
	} else if(sub_result.case_no == _COMP_SUBSET){
		//if(_DEBUG)
		printf("show_subtract: case 2(1) (A is completely sub set of B) = (%u, %u), (%u, %u)\n", sub_result.start1, sub_result.stop1, sub_result.start2, sub_result.stop2);
	}else if(sub_result.case_no == _INTESECTION){
		//if(_DEBUG)
		printf("show_subtract: case 3(1), 3(2) (A is intersect with B) = (%u, %u), (%u, %u)\n", sub_result.start1, sub_result.stop1, sub_result.start2, sub_result.stop2);
	}else if(sub_result.case_no == _NO_CASE)
		printf("show_subtract: don't match any cases\n");
	return;
}

/*	N-ary Tree structure
 * 		root --> NULL
 * 		|
 * 		V
 * 		child(1)-->sibling(1)-->sibling(2)...sibling(n) -- dest_port level
 * 		|
 * 		V
 * 		child(2)-->sibling(1)-->sibling(2)...sibling(n) -- dest_ip level
 * 		|
 * 		V
 * 		child(3)-->slibing(1)................sibling(n) -- src_ip level
 * 		|
 * 		V
 * 		child(4)-->slibing(1)................sibling(n) -- proto level
 * 		|
 * 		V
 * 		child(5)-->slibing(1)................sibling(n) -- action level
 * 		|
 * 		V
 * 		NULL
 * */

void create_FDSD_tree(node *n, dsd_struct rule_x){
	if(n == NULL) return;

	if(n->child == NULL){ // create first set of data in tree (first rule)
		add_child(n, rule_x.start_dest_port, rule_x.stop_dest_port); //add first dest_port
		add_child(n, rule_x.start_dest_ip, rule_x.stop_dest_ip); //add first dest_ip
		add_child(n, rule_x.start_src_ip, rule_x.stop_src_ip); //add first src_ip
		add_child(n, rule_x.start_proto, rule_x.stop_proto); //add first proto
		add_child(n, rule_x.action, rule_x.in_out); //add first action and interface

	}else { // if dest_port level is not NULL (it's not the first rule)

		stack *s1, *s2;
		queue *q_dport;
		data point;
		lst_node lst_n;
		s1 = init_stack();
		s2 = init_stack();
		q_dport = init_queue();

		node *dest_port = n->child;
		point.start = rule_x.start_dest_port;
		point.stop = rule_x.stop_dest_port;
		push(s1, point);

		while(dest_port){

			while(!stack_is_empty(s1)){
				point = pop(s1);
				subtract(dest_port->start, dest_port->stop, point.start, point.stop);
				//show_subtract();

				if(sub_result.case_no == _DISJOINT){
					lst_n.case_no = _DISJOINT;
					lst_n.addr = dest_port->child;
					enqueue(q_dport, lst_n);
					point.start = sub_result.start1;
					point.stop = sub_result.stop1;
					push(s2, point);

				}else if(sub_result.case_no == _COMP_SUPERSET){
					lst_n.case_no = _COMP_SUPERSET;
					lst_n.addr = dest_port->child;
					enqueue(q_dport, lst_n);

				}else if(sub_result.case_no == _SOME_SUBSET){
					lst_n.case_no = _SOME_SUBSET;
					lst_n.addr = dest_port->child;
					enqueue(q_dport, lst_n);
					point.start = sub_result.start1;
					point.stop = sub_result.stop1;
					push(s2, point);

				}else if(sub_result.case_no == _COMP_SUBSET){
					lst_n.case_no = _COMP_SUBSET;
					lst_n.addr = dest_port->child;
					enqueue(q_dport, lst_n);
					point.start = sub_result.start1;
					point.stop = sub_result.stop1;
					push(s2, point);
					point.start = sub_result.start2;
					point.stop = sub_result.stop2;
					push(s2, point);

				}else if(sub_result.case_no == _INTESECTION){
					lst_n.case_no = _INTESECTION;
					lst_n.addr = dest_port->child;
					enqueue(q_dport, lst_n);
					point.start = sub_result.start1;
					point.stop = sub_result.stop1;
					push(s2, point);
					point.start = sub_result.start2;
					point.stop = sub_result.stop2;
					push(s2, point);

				}
			}

			while(!stack_is_empty(s2)){
				point = pop(s2);
				push(s1, point);
			}

			dest_port = dest_port->next;
		}

		/* add all disjoint dest_port list to FDSD tree */
		while(!stack_is_empty(s1)){
			point = pop(s1);
			node *x = add_sibling(n->child, point.start, point.stop); // add all new dest_ports (all disjoint)
			add_child(x, rule_x.start_dest_ip, rule_x.stop_dest_ip);
			add_child(x, rule_x.start_src_ip, rule_x.stop_src_ip);
			add_child(x, rule_x.start_proto, rule_x.stop_proto);
			add_child(x, rule_x.action, rule_x.in_out);
		}

/************************************************************************************************/
        /*----------------------------- dest_ip section ---------------------------------------*/
		/* add super set, some subset and completely subset list to FDSD tree */

		node *dest_ip;
		queue *q_dip;
		q_dip = init_queue();

		while(!queue_is_empty(q_dport)){
			lst_n = dequeue(q_dport);
			dest_ip = lst_n.addr;
			node *dest_ip_head = lst_n.addr; // keeps head address of all siblings

			if(lst_n.case_no == _DISJOINT){ //---------------- dest_ip
				// nothing else because it was added in all disjoint case above
			}else if(lst_n.case_no == _COMP_SUPERSET || _SOME_SUBSET || _COMP_SUBSET || _INTESECTION){ // dest_ip
				// add code for dest_ip
				point.start = rule_x.start_dest_ip;
				point.stop = rule_x.stop_dest_ip;
				push(s1, point);

				while(dest_ip){
					while(!stack_is_empty(s1)){
						point = pop(s1);
						subtract(dest_ip->start, dest_ip->stop, point.start, point.stop);
						//show_subtract();

						if(sub_result.case_no == _DISJOINT){
							lst_n.case_no = _DISJOINT;
							lst_n.addr = dest_ip->child;  // keeps an address of src_ip
							enqueue(q_dip, lst_n);
							point.start = sub_result.start1;
							point.stop = sub_result.stop1;
							push(s2, point);

						}else if(sub_result.case_no == _COMP_SUPERSET){
							lst_n.case_no = _COMP_SUPERSET;
							lst_n.addr = dest_ip->child;
							enqueue(q_dip, lst_n);

						}else if(sub_result.case_no == _SOME_SUBSET){
							lst_n.case_no = _SOME_SUBSET;
							lst_n.addr = dest_ip->child;
							enqueue(q_dip, lst_n);
							point.start = sub_result.start1;
							point.stop = sub_result.stop1;
							push(s2, point);

						}else if(sub_result.case_no == _COMP_SUBSET){
							lst_n.case_no = _COMP_SUBSET;
							lst_n.addr = dest_ip->child;
							enqueue(q_dip, lst_n);
							point.start = sub_result.start1;
							point.stop = sub_result.stop1;
							push(s2, point);
							point.start = sub_result.start2;
							point.stop = sub_result.stop2;
							push(s2, point);

						}else if(sub_result.case_no == _INTESECTION){
							lst_n.case_no = _INTESECTION;
							lst_n.addr = dest_ip->child;
							enqueue(q_dip, lst_n);
							point.start = sub_result.start1;
							point.stop = sub_result.stop1;
							push(s2, point);
							point.start = sub_result.start2;
							point.stop = sub_result.stop2;
							push(s2, point);

						}
					}

					while(!stack_is_empty(s2)){
						point = pop(s2);
						push(s1, point);
					}

					dest_ip = dest_ip->next;
				}

				//show_queue(q_dip);
				//printf("-------------------\n");
				//show_stack(s1);

				// add all disjoint dest_ip list to FDSD tree
				while(!stack_is_empty(s1)){
					point = pop(s1);
					node *x = add_sibling(dest_ip_head, point.start, point.stop); // add all new dest_ip (all disjoint)
					add_child(x, rule_x.start_src_ip, rule_x.stop_src_ip);
					add_child(x, rule_x.start_proto, rule_x.stop_proto);
					add_child(x, rule_x.action, rule_x.in_out);
				}

		        //----------------------------- src_ip section ---------------------------------------
				// add super set, some subset, completely subset and disjoint list to FDSD tree

				node *src_ip;
				queue *q_sip;
				q_sip = init_queue();
				while(!queue_is_empty(q_dip)){
					lst_n = dequeue(q_dip);
					src_ip = lst_n.addr;
					node *src_ip_head = lst_n.addr;

					if(lst_n.case_no == _DISJOINT){ //-------------------------------- src_ip
						// nothing else
					}else if(lst_n.case_no == _COMP_SUPERSET || _SOME_SUBSET || _COMP_SUBSET || _INTESECTION){ // src_ip
						point.start = rule_x.start_src_ip;
						point.stop = rule_x.stop_src_ip;
						push(s1, point);

						while(src_ip){
							while(!stack_is_empty(s1)){
								point = pop(s1);
								subtract(src_ip->start, src_ip->stop, point.start, point.stop);
								//show_subtract();

								if(sub_result.case_no == _DISJOINT){
									lst_n.case_no = _DISJOINT;
									lst_n.addr = src_ip->child;
									enqueue(q_sip, lst_n);
									point.start = sub_result.start1;
									point.stop = sub_result.stop1;
									push(s2, point);

								}else if(sub_result.case_no == _COMP_SUPERSET){
									lst_n.case_no = _COMP_SUPERSET;
									lst_n.addr = src_ip->child;
									enqueue(q_sip, lst_n);

								}else if(sub_result.case_no == _SOME_SUBSET){
									lst_n.case_no = _SOME_SUBSET;
									lst_n.addr = src_ip->child;
									enqueue(q_sip, lst_n);
									point.start = sub_result.start1;
									point.stop = sub_result.stop1;
									push(s2, point);

								}else if(sub_result.case_no == _COMP_SUBSET){
									lst_n.case_no = _COMP_SUBSET;
									lst_n.addr = src_ip->child;
									enqueue(q_sip, lst_n);
									point.start = sub_result.start1;
									point.stop = sub_result.stop1;
									push(s2, point);
									point.start = sub_result.start2;
									point.stop = sub_result.stop2;
									push(s2, point);

								}else if(sub_result.case_no == _INTESECTION){
									lst_n.case_no = _INTESECTION;
									lst_n.addr = src_ip->child;
									enqueue(q_sip, lst_n);
									point.start = sub_result.start1;
									point.stop = sub_result.stop1;
									push(s2, point);
									point.start = sub_result.start2;
									point.stop = sub_result.stop2;
									push(s2, point);

								}
							}

							while(!stack_is_empty(s2)){
								point = pop(s2);
								push(s1, point);
							}

							src_ip = src_ip->next;
						}

						while(!stack_is_empty(s1)){
							point = pop(s1);
							node *x = add_sibling(src_ip_head, point.start, point.stop); // add all new src_ip (all disjoint)
							add_child(x, rule_x.start_proto, rule_x.stop_proto);
							add_child(x, rule_x.action, rule_x.in_out);
						}

						// --------------------------------------- protocol section ---------------------------------
						node *proto;
						queue *q_pro;
						q_pro = init_queue();
						while(!queue_is_empty(q_sip)){
							lst_n = dequeue(q_sip);
							proto = lst_n.addr;
							node *proto_head = lst_n.addr;

							if(lst_n.case_no == _DISJOINT){ //----- protocol
								// nothing else
							}else if(lst_n.case_no == _COMP_SUPERSET || _SOME_SUBSET || _COMP_SUBSET || _INTESECTION){ // protocol
								point.start = rule_x.start_proto;
								point.stop = rule_x.stop_proto;
								push(s1, point);

								while(proto){
									while(!stack_is_empty(s1)){
										point = pop(s1);
										subtract(proto->start, proto->stop, point.start, point.stop);
										//show_subtract();

										if(sub_result.case_no == _DISJOINT){
											lst_n.case_no = _DISJOINT;
											lst_n.addr = proto->child;
											enqueue(q_pro, lst_n);
											point.start = sub_result.start1;
											point.stop = sub_result.stop1;
											push(s2, point);

										}else if(sub_result.case_no == _COMP_SUPERSET){
											lst_n.case_no = _COMP_SUPERSET;
											lst_n.addr = proto->child;
											enqueue(q_pro, lst_n);

										}else if(sub_result.case_no == _SOME_SUBSET){
											lst_n.case_no = _SOME_SUBSET;
											lst_n.addr = proto->child;
											enqueue(q_pro, lst_n);
											point.start = sub_result.start1;
											point.stop = sub_result.stop1;
											push(s2, point);

										}else if(sub_result.case_no == _COMP_SUBSET){
											lst_n.case_no = _COMP_SUBSET;
											lst_n.addr = proto->child;
											enqueue(q_pro, lst_n);
											point.start = sub_result.start1;
											point.stop = sub_result.stop1;
											push(s2, point);
											point.start = sub_result.start2;
											point.stop = sub_result.stop2;
											push(s2, point);

										}else if(sub_result.case_no == _INTESECTION){
											lst_n.case_no = _INTESECTION;
											lst_n.addr = proto->child;
											enqueue(q_pro, lst_n);
											point.start = sub_result.start1;
											point.stop = sub_result.stop1;
											push(s2, point);
											point.start = sub_result.start2;
											point.stop = sub_result.stop2;
											push(s2, point);

										}
									}

									while(!stack_is_empty(s2)){
										point = pop(s2);
										push(s1, point);
									}

									proto = proto->next;
								}

								while(!stack_is_empty(s1)){
									point = pop(s1);
									node *x = add_sibling(proto_head, point.start, point.stop); // add all new protocol (all disjoint)
									add_child(x, rule_x.action, rule_x.in_out);
								}
							}
						}
					}
				}
			}
		}
	}

	return;
}

void show_iptables(dsd_struct* iptables){
	int i;
	//printf("%-3d %-6s %-16s %-16s %-10s %-16s %-16s %-10s %-9s %-10s\n", i, in_out, src_ip, src_mask, src_port, dest_ip, dest_mask, dest_port, proto, action);
	printf("No. in_out \tdest_port \t dest_ip \t\t src_ip \t\t src_port \t proto \t action\n");
	for(i = 0; i < rule_count; i++){
		printf("%-3d %-11u %-5u,%-10u %-10lu,%-12lu %-10lu,%-12lu %u,%-13u %-3u,%-5u %-8u\n",
				i+1,
				iptables[i].in_out,
				iptables[i].start_dest_port, iptables[i].stop_dest_port,
				iptables[i].start_dest_ip, iptables[i].stop_dest_ip,
				iptables[i].start_src_ip, iptables[i].stop_src_ip,
				iptables[i].start_src_port, iptables[i].stop_src_port,
				iptables[i].start_proto, iptables[i].stop_proto,
				iptables[i].action);

	}
	return;
}

node *FDSD(dsd_struct* iptables){
	int i;

	//show_iptables(iptables);
	node *root = new_node(0, 0);  //create root node of FDSD tree

	for(i = 0; i < rule_count; i++){ // loop each rule to create FDSD tree
		create_FDSD_tree(root, iptables[i]);
	}

//	preorder_traversal(root->child);

	return (root->child);
}

char *trim_newline(char *str){
    int i = 0;
    int len = strlen(str);
    char copy[len-1];

    for(i = 0; i < len-1; i++){
    	copy[i] = *str;
    	str++;
    }
    str = (char *)copy;
    return str;
}

int split(char *str, const char *delim, char ***array, int *length) {
	int i = 0;
	char *token;
	char **res = (char **) malloc(0 * sizeof(char *));

	/* get the first token */
	token = strtok(str, delim);
	while( token != NULL ){
		res = (char **) realloc(res, (i + 1) * sizeof(char *));
        res[i] = token;
        i++;
        token = strtok(NULL, delim);
	}
	*array = res;
	*length = i;
	return 1;
}

unsigned int count_bit_subnetmask(char *subnetmask){
	int O1, O2, O3, O4;
	sscanf(subnetmask, "%d.%d.%d.%d", &O1, &O2, &O3, &O4);
	if(_DEBUG) {
		printf("%d\n", O1);
		printf("%d\n", O2);
		printf("%d\n", O3);
		printf("%d\n", O4);
	}

	int i = 0;
	int count = 0;
	for(i = 7; i >= 0; i--){
		if((O1 & (1 << i)) != 0){
			count++;
		} else break;
	}
	for(i = 7; i >= 0; i--){
		if((O2 & (1 << i)) != 0){
			count++;
		} else break;
	}
	for(i = 7; i >= 0; i--){
		if((O3 & (1 << i)) != 0){
			count++;
		} else break;
	}
	for(i = 7; i >= 0; i--){
		if((O4 & (1 << i)) != 0){
			count++;
		} else break;
	}
	return count;
}

/* Convert the given ip address in native byte order to a printable string */
char *my_ntoa(unsigned int ip) {
	struct in_addr addr;
	addr.s_addr = htonl(ip);
	return inet_ntoa(addr);
}

// calculate network address, broadcast, first ip, last ip by ip address and netmask length
void calculate_IP_addresses(char *ip, char *ip_netmask){
	struct in_addr addr, netmask;
	unsigned int mask, network, hostmask, broadcast;
	int maskbits;
	int i, bitmask_len;
	char *tmp;

	/* Calculate length of ip netmask */
	bitmask_len = count_bit_subnetmask(ip_netmask);

	/* Convert the string ip address to network order address */
	if (!inet_aton(ip, &addr) ) {
		fprintf(stderr,"%s is not a valid IP address\n", ip);
		exit(EXIT_FAILURE);
	}

	maskbits = bitmask_len;

	if(bitmask_len >= 32){
		ip_struct.network_ip = ip;
		ip_struct.broadcast_ip = ip;
		ip_struct.host_count = 1;
		ip_struct.first_ip = ip;
		ip_struct.last_ip = ip;
		ip_struct.prefix = 32;
		return;
	}

	if(bitmask_len == 31){
		mask = 0;
		for(i = 0; i < maskbits; i++) mask |= 1 << (31 - i);
		netmask.s_addr = htonl(mask);
		network = ntohl(addr.s_addr) & ntohl(netmask.s_addr);
		tmp = my_ntoa(network);
		ip_struct.network_ip = malloc(sizeof(char) * strlen(tmp));
		ip_struct.first_ip = malloc(sizeof(char) * strlen(tmp));
		strcpy(ip_struct.network_ip, tmp);
		strcpy(ip_struct.first_ip, tmp);

		hostmask = ~ntohl(netmask.s_addr);
		broadcast = network | hostmask;
		tmp = my_ntoa(broadcast);
		ip_struct.broadcast_ip = malloc(sizeof(char) * strlen(tmp));
		ip_struct.last_ip = malloc(sizeof(char) * strlen(tmp));
		strcpy(ip_struct.broadcast_ip, tmp);
		strcpy(ip_struct.last_ip, tmp);
		ip_struct.host_count = 2;
		ip_struct.prefix = 31;

		return;
	}


	if (maskbits < 1 || maskbits > 30 ) {
		fprintf(stderr,"Invalid net mask bits (1-30): %d\n", maskbits);
		exit(EXIT_FAILURE);
	}

	/* Create the netmask from the number of bits */
	mask = 0;
	for(i = 0; i < maskbits; i++) mask |= 1 << (31 - i);

	netmask.s_addr = htonl(mask);

	if(_DEBUG) printf("calculate_IP_addresses: IP address   %s\n", inet_ntoa(addr));
	if(_DEBUG) printf("calculate_IP_addresses: Netmask      %s\n", inet_ntoa(netmask));
	if(_DEBUG) printf("calculate_IP_addresses: Netmask bits %d\n", maskbits);

	network = ntohl(addr.s_addr) & ntohl(netmask.s_addr);

	tmp = my_ntoa(network);
	ip_struct.network_ip = malloc(sizeof(char) * strlen(tmp));
	strcpy(ip_struct.network_ip, tmp);
	if(_DEBUG) printf("calculate_IP_addresses: Network      %s\n", my_ntoa(network));

	hostmask = ~ntohl(netmask.s_addr);
	broadcast = network | hostmask;

	tmp = my_ntoa(broadcast);
	ip_struct.broadcast_ip = malloc(sizeof(char) * strlen(tmp));
	strcpy(ip_struct.broadcast_ip, tmp);

	if(_DEBUG) printf("calculate_IP_addresses: Broadcast    %s\n", my_ntoa(broadcast));
	if(_DEBUG) printf("calculate_IP_addresses: Hosts        %s\n", my_ntoa(network+1));

	tmp = my_ntoa(network+1);
	ip_struct.first_ip = malloc(sizeof(char) * strlen(tmp));
	strcpy(ip_struct.first_ip, tmp);

	if(_DEBUG) printf("calculate_IP_addresses:    to        %s\n", my_ntoa(broadcast-1));

	tmp = my_ntoa(broadcast-1);
	ip_struct.last_ip = malloc(sizeof(char) * strlen(tmp));
	strcpy(ip_struct.last_ip, tmp);

	if(_DEBUG) printf("calculate_IP_addresses: Host count   %d\n", broadcast-network-1);
	ip_struct.host_count = broadcast-network+1;

	ip_struct.prefix = bitmask_len;

	return;
}

unsigned char convert_proto_to_int(char *any_proto){
    unsigned int proto = 0;
    int i = 0;
    if (any_proto == _ANY) {
        return _MAX_PROTO;
    }

    if(strcmp(_TCP, any_proto) == 0){
    	return _TCP_PROTO;
    }

    if(strcmp(_UDP, any_proto) == 0){
    	return _UDP_PROTO;
    }

    if(strcmp(_ICMP, any_proto) == 0){
    	return _ICMP_PROTO;
    }

    if(strcmp(_ANY, any_proto) == 0){
        	return _ALL_PROTO;
        }

    while (any_proto[i] != '\0') {
        proto = proto * 10 + (any_proto[i] - '0');
        ++i;
    }
    return proto;
}

unsigned int convert_port_to_int(char *any_port){
    unsigned int port = 0;
    int i = 0;
    if (any_port == _ANY) {
        return _MAX_PORT;
    }

    while (any_port[i] != '\0') {
        port = port * 10 + (any_port[i] - '0');
        ++i;
    }
    return port;
}

unsigned int convert_IP_to_int(char *ipadr){
	if(strcmp(ipadr, _ANY) == 0) return _MAX_IPV4;
	unsigned int num = 0, val;
    char *tok, *ptr;
    char *ip;
    ip = malloc(sizeof(char) * strlen(ipadr));
    strcpy(ip, ipadr);
    tok = strtok(ip, ".");
    while( tok != NULL){
    	val = strtoul(tok, &ptr, 0);
        num = (num << 8) + val;
        tok = strtok(NULL, ".");
    }
    return(num);
}

char *convert_int_to_IP(unsigned int ip){
	char *buffer;
	unsigned char bytes[4];
	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;
	//printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
	//sprintf(buffer, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
	buffer = malloc((sizeof(char) * 8));
	sprintf(buffer, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
	//printf("%s\n", buffer);
	return buffer;
}

unsigned int count_rule_in_file(void){
	FILE *FWR;
	char * line = NULL;
	size_t len = 0;
	ssize_t read;
	unsigned int count = 0;
	FWR = fopen(_FW_RULE_NOR_NAME, _O_READ);
	if(FWR != NULL){
		while ((read = getline(&line, &len, FWR)) != -1) {
			count++;
		}
	}else{
		return 0;
	}

	fclose(FWR);
	return count;
}

dsd_struct* preprocess_FDSD(void){
	FILE *FWR;
	char **rule_x;
	int count, i;
	unsigned int rule_index;
	dsd_struct* dsd;

	rule_count = count_rule_in_file();
	if(rule_count > 0){
		if(_DEBUG) printf("preprocess_FDSD:  the number of firewall rules = %u\n", rule_count);

		FWR = fopen(_FW_RULE_NOR_NAME, _O_READ);
		if(FWR != NULL){
			dsd_struct* dsd_rules = malloc(rule_count * sizeof *dsd_rules);
			rule_index = 0;
			char * line = NULL;
			size_t len = 0;
			ssize_t read;

			while ((read = getline(&line, &len, FWR)) != -1) {
				if(_DEBUG) printf("preprocess_FDSD: %s", line);
				rule_x = NULL;
				count = 0;
				split(line, " ", &rule_x, &count);
				if(_DEBUG) printf("Found %d tokens.\n", count);
				if(_DEBUG) for (i = 0; i < count; i++) printf("string #%d: %s\n", i, rule_x[i]);

				// pre-process each firewall rule
				// first prepare in/out at rule_x[0]

				dsd_rules[rule_index].in_out = get_in_out(rule_x[0]);
				if(_DEBUG) printf("preprocess_FDSD: inbound or outbound packet (%s) =  %u\n", rule_x[0], dsd_rules[rule_index].in_out);

				//calculate network_ip and broadcast_ip of src_ip at rule_x[1] = src_ip, rule_x[2] = src_netmask, store in dsd struct
				if(strcmp(_ANY, rule_x[1]) == 0){
					dsd_rules[rule_index].start_src_ip = 0;
					dsd_rules[rule_index].stop_src_ip = _MAX_IPV4;
					ip_struct.host_count = _MAX_IPV4;
					if(_DEBUG) printf("preprocess_FDSD: start src_ip - stop src_ip = %u - %u\n", dsd_rules[rule_index].start_src_ip, dsd_rules[rule_index].stop_src_ip);
					if(_DEBUG) printf("preprocess_FDSD: host count = %u\n", ip_struct.host_count);
				}else{
					calculate_IP_addresses(rule_x[1], rule_x[2]);
					if(_DEBUG) printf("----> network ip = %s\n", ip_struct.network_ip);
					if(_DEBUG) printf("----> broadcast ip = %s\n", ip_struct.broadcast_ip);
					dsd_rules[rule_index].start_src_ip = convert_IP_to_int(ip_struct.network_ip);
					dsd_rules[rule_index].stop_src_ip = convert_IP_to_int(ip_struct.broadcast_ip);
					if(_DEBUG) printf("preprocess_FDSD: start src_ip - stop src_ip = %u - %u\n", dsd_rules[rule_index].start_src_ip, dsd_rules[rule_index].stop_src_ip);
					if(_DEBUG) printf("preprocess_FDSD: host count = %u\n", ip_struct.host_count);
				}

				//calculate network_ip and broadcast_ip of dest_ip at rule_x[4, 5]
				if(strcmp(_ANY, rule_x[4]) == 0){
					dsd_rules[rule_index].start_dest_ip = 0;
					dsd_rules[rule_index].stop_dest_ip = _MAX_IPV4;
					ip_struct.host_count = _MAX_IPV4;
					if(_DEBUG) printf("preprocess_FDSD: start dest_ip - stop dest_ip = %u - %u\n", dsd_rules[rule_index].start_dest_ip, dsd_rules[rule_index].stop_dest_ip);
					if(_DEBUG) printf("preprocess_FDSD: host count = %u\n", ip_struct.host_count);
				}else{
					calculate_IP_addresses(rule_x[4], rule_x[5]);
					if(_DEBUG) printf("----> network ip = %s\n", ip_struct.network_ip);
					if(_DEBUG) printf("----> broadcast ip = %s\n", ip_struct.broadcast_ip);
					dsd_rules[rule_index].start_dest_ip = convert_IP_to_int(ip_struct.network_ip);
					dsd_rules[rule_index].stop_dest_ip = convert_IP_to_int(ip_struct.broadcast_ip);
					if(_DEBUG) printf("preprocess_FDSD: start dest_ip - stop dest_ip = %u - %u\n", dsd_rules[rule_index].start_dest_ip, dsd_rules[rule_index].stop_dest_ip);
					if(_DEBUG) printf("preprocess_FDSD: host count = %u\n", ip_struct.host_count);
				}

				//calculate src_port at rule_x[3]
				if(strcmp(_ANY, rule_x[3]) == 0){
					dsd_rules[rule_index].start_src_port = 0;
					dsd_rules[rule_index].stop_src_port = _MAX_PORT;
					if(_DEBUG) printf("preprocess_FDSD: start src_port - stop src_port = %u - %u\n", dsd_rules[rule_index].start_src_port, dsd_rules[rule_index].stop_src_port);
				}else{
					unsigned int port;
					port = convert_port_to_int(rule_x[3]);
					dsd_rules[rule_index].start_src_port = port;
					dsd_rules[rule_index].stop_src_port = port;
					if(_DEBUG) printf("preprocess_FDSD: start src_port - stop src_port = %u - %u\n", dsd_rules[rule_index].start_src_port, dsd_rules[rule_index].stop_src_port);
				}

				//calculate dest_port at rule_x[6]
				if(strcmp(_ANY, rule_x[6]) == 0){
					dsd_rules[rule_index].start_dest_port = 0;
					dsd_rules[rule_index].stop_dest_port = _MAX_PORT;
					if(_DEBUG) printf("preprocess_FDSD: start dest_port - stop dest_port = %u - %u\n", dsd_rules[rule_index].start_dest_port, dsd_rules[rule_index].stop_dest_port);
				}else{
					unsigned int port;
					port = convert_port_to_int(rule_x[6]);
					dsd_rules[rule_index].start_dest_port = port;
					dsd_rules[rule_index].stop_dest_port = port;
					if(_DEBUG) printf("preprocess_FDSD: start dest_port - stop dest_port = %u - %u\n", dsd_rules[rule_index].start_dest_port, dsd_rules[rule_index].stop_dest_port);
				}

				//calculate protocol at rule_x[7]
				if(strcmp(_ANY, rule_x[7]) == 0){
					dsd_rules[rule_index].start_proto = 0;
					dsd_rules[rule_index].stop_proto = _MAX_PROTO;
					if(_DEBUG) printf("preprocess_FDSD: start proto - stop proto = %d - %d\n", dsd_rules[rule_index].start_proto, dsd_rules[rule_index].stop_proto);
				}else{
					unsigned char proto;
					proto = convert_proto_to_int(rule_x[7]);
					dsd_rules[rule_index].start_proto = proto;
					dsd_rules[rule_index].stop_proto = proto;
					if(_DEBUG) printf("preprocess_FDSD: start proto - stop proto (single proto) = %u - %u\n", proto);
				}

				//calculate action at rule_x[8]
				char *act = trim_newline(rule_x[8]);
				if(strcmp(_ACCEPT, act) == 0){
					dsd_rules[rule_index].action = _YES;
					if(_DEBUG) printf("preprocess_FDSD: action = %d\n", dsd_rules[rule_index].action);
				}else if(strcmp(_DENY, act) == 0){
					dsd_rules[rule_index].action = _NO;
					if(_DEBUG) printf("preprocess_FDSD: action = %d\n", dsd_rules[rule_index].action);
				}

				if(_DEBUG) printf("-----------------------------------------------\n");
				rule_index++;
			}
			dsd = dsd_rules;

		}else{
			printf("preprocess_FDSD: Cannot open %s for reading\n", _FW_RULE_NOR_NAME);
			exit(EXIT_FAILURE);
		}

	}else{
		printf("preprocess_FDSD:  haven't any rule in the firewall rule\n");
		exit(EXIT_FAILURE);
	}

	return dsd;
}

void open_help(void){
	FILE *pf;
	pf = fopen(_FW_README, _O_READ);
	if(pf != NULL){
		char * line = NULL;
		size_t len = 0;
		ssize_t read;
		while ((read = getline(&line, &len, pf)) != -1) {
			//printf("Retrieved line of length %zu :\n", read);
			printf("%s", line);
		}
		printf("\n");
	}
	fclose(pf);
	return;
}

node *free_FDSD_tree(node *n){
	if(n == NULL) return NULL;
	if(n){
		free_FDSD_tree(n->child);
		free_FDSD_tree(n->next);
		//printf("free %u, %u\n", n->start, n->stop);
		free(n);
	}
	return NULL;
}

void apply(void){
	// call function for preparing firewall preparing decision state diagram (FDSD)
	dsd_struct* iptables;
	iptables = preprocess_FDSD();

	//call function FDSD to improve firewall rule conflicts and reduce overlap rules

	node *fdsd = FDSD(iptables);
	//preorder_traversal(fdsd);
	write_to_procf(fdsd);
	//printf("free FDSD tree (OK).\n");
	free_FDSD_tree(fdsd);

	return;
}

void del_fw_rule(const char* optarg){
	int no;
	FILE *pf1;
	FILE *pf2;
	char ch;
	int count = 1;
	no = atoi(optarg);
	if(valid_digit((char *)optarg) == _YES && (no > 0)){
		if(_DEBUG)printf("Optarg is digit and > 0\n");
		pf1 = fopen(_FW_RULE_NOR_NAME, _O_READ);
		pf2 = fopen(_FW_RULE_TMP_NAME, _O_WRITE);
		if (pf1 == NULL){
			printf("Cannot open %s for reading\n", _FW_RULE_NOR_NAME);
			exit(EXIT_FAILURE);
		}
		if(pf2 == NULL){
			printf("Cannot open %s for writing\n", _FW_RULE_TMP_NAME);
			exit(EXIT_FAILURE);
		}

		char * line = NULL;
		size_t len = 0;
		ssize_t read;

		while ((read = getline(&line, &len, pf1)) != -1) {
		        //printf("Retrieved line of length %zu :\n", read);
				if(count == no){

				}else{
					if(_DEBUG) printf("%s", line);
					fputs(line, pf2);
				}
				count++;
		    }

		//printf("\n");
		fclose(pf1);
		fclose(pf2);
		remove(_FW_RULE_NOR_NAME);
		//rename the file firewall_rule.tmp to original name
		rename(_FW_RULE_TMP_NAME, _FW_RULE_NOR_NAME);

	}else if(!strcmp(_ALL, lowercase(optarg))){
		pf1 = fopen(_FW_RULE_NOR_NAME, _O_WRITE);
		if (pf1 == NULL){
			printf("Cannot open %s for reading\n", _FW_RULE_NOR_NAME);
			exit(EXIT_FAILURE);
		}
		fclose(pf1);
	}else{
		printf("Bad rule number to delete (must be 1 - N, all and no character)\n");
		exit(EXIT_FAILURE);
	}
	return;
}

char *format_fw_rule(){
	int total_len = 0;
	char *in_out;
	char *src_ip;
	char *src_mask;
	char *src_port;
	char *dest_ip;
	char *dest_mask;
	char *dest_port;
	char *proto;
	char *action;

	if(firewall_rule.in_out >= _OUT && firewall_rule.in_out <= _IN){
		total_len += strlen(print(firewall_rule.in_out));
		in_out = print(firewall_rule.in_out);
		//printf("in out length = %d\n", total_len);
	}else {
		printf("Bad in or out packet flows (need to be identified [in or out])\n");
		return NULL;
	}

	if(firewall_rule.src_ip == NULL){
		total_len += 3;		// for "any" word
		src_ip = _ANY;
	}else {
		total_len += strlen(firewall_rule.src_ip);
		src_ip = firewall_rule.src_ip;
	}

	if(firewall_rule.src_netmask == NULL){
		total_len += 3;
		src_mask = _ANY;
	}else {
		total_len += strlen(firewall_rule.src_netmask);
		src_mask = firewall_rule.src_netmask;
	}

	if(firewall_rule.src_port == NULL){
		total_len += 3;
		src_port = _ANY;
	}else {
		total_len += strlen(firewall_rule.src_port);
		src_port = firewall_rule.src_port;
	}

	if(firewall_rule.dest_ip == NULL){
		total_len += 3;
		dest_ip = _ANY;
	}else {
		total_len += strlen(firewall_rule.dest_ip);
		dest_ip = firewall_rule.dest_ip;
	}

	if(firewall_rule.dest_netmask == NULL){
		total_len += 3;
		dest_mask = _ANY;
	}else {
		total_len += strlen(firewall_rule.dest_netmask);
		dest_mask = firewall_rule.dest_netmask;
	}

	if(firewall_rule.dest_port == NULL){
		total_len += 3;
		dest_port = _ANY;
	}else {
		total_len += strlen(firewall_rule.dest_port);
		dest_port = firewall_rule.dest_port;
	}

	if(firewall_rule.proto == NULL){
		total_len += 3;
		proto = _ANY;
	}else {
		total_len += strlen(firewall_rule.proto);
		proto = firewall_rule.proto;
	}

	if(firewall_rule.action == NULL){
		printf("Bad action (need to be identified [accept or deny])\n");
		return NULL;
	}else {
		total_len += strlen(firewall_rule.action);
		action = firewall_rule.action;
		//printf("action length = %d\n", strlen(firewall_rule.action));
	}

	total_len += 9; // 8 char for 8 spaces
	if(_DEBUG) printf("Total len = %d\n", total_len);

	char *const strBuf = malloc(total_len);
	if (strBuf == NULL){
		 fprintf(stderr, "malloc failed\n");
	     exit(EXIT_FAILURE);
	 }
	//strBuf[total_len] = '\0';
	snprintf(strBuf, total_len, "%s %s %s %s %s %s %s %s %s", in_out, src_ip, src_mask, src_port, dest_ip, dest_mask, dest_port, proto, action);
	if(_DEBUG) printf("%s\n", strBuf);
	return strBuf;
}

void print_fw_rule(){
	FILE *pf;
	int i = 0;
	char in_out[3];
	char src_ip[20];
	char src_mask[20];
	char src_port[8];
	char dest_ip[20];
	char dest_mask[20];
	char dest_port[8];
	char proto[5];
	char action[8];

	pf = fopen(_FW_RULE_NOR_NAME, _O_READ);
	if (pf == NULL){
		if(_DEBUG) printf("Cannot open %s for reading\n", _FW_RULE_NOR_NAME);
		printf(_BOLDRED);
		printf("%-3s %-6s %-16s %-16s %-10s %-16s %-16s %-10s %-9s %-10s\n", "no.", "in/out", "src_ip", "src_netmask", "src_port", "dest_ip", "dest_netmask", "dest_port", "protocol", "action");
		printf(_RESET);
		return;
	}else {
		printf(_BOLDRED);
		printf("%-3s %-6s %-16s %-16s %-10s %-16s %-16s %-10s %-9s %-10s\n", "no.", "in/out", "src_ip", "src_netmask", "src_port", "dest_ip", "dest_netmask", "dest_port", "protocol", "action");
		printf(_RESET);
		while(fscanf(pf, "%s %s %s %s %s %s %s %s %s", in_out, src_ip, src_mask, src_port, dest_ip, dest_mask, dest_port, proto, action) != EOF) {
		  i++;
		  printf("%-3d %-6s %-16s %-16s %-10s %-16s %-16s %-10s %-9s %-10s\n", i, in_out, src_ip, src_mask, src_port, dest_ip, dest_mask, dest_port, proto, action);
		}
	}

	fclose(pf);
	return;
}

void write_fw_rule(unsigned char rule_type){
	FILE *pf;
	FILE *pf2;
	char *fw_rule;
	pf = fopen(_FW_RULE_NOR_NAME, _O_WRITE_APPEND);
	if(pf != NULL){
		fw_rule = format_fw_rule();
		if(fw_rule == NULL){
			printf("Format of firewall rule error!\n");
			exit(EXIT_FAILURE);
		}else {
			if(_DEBUG) printf("Write a rule = %s\n", fw_rule);

				char * line = NULL;
				size_t len = 0;
				ssize_t read;

				while ((read = getline(&line, &len, pf)) == -1) { //firewall rule has not any rule exist (the first rule is inserted)
					fprintf(pf, "%s\n", fw_rule);
					//fputs(pf, fw_rule);
					fclose(pf);
					return;
				}

				pf2 = fopen(_FW_RULE_TMP_NAME, _O_WRITE_APPEND);
				if(pf2 != NULL){
					line = NULL;
					size_t len = 0;

					//fputs(fw_rule, pf2);
					fprintf(pf2, "%s\n", fw_rule);
					rewind(pf);
					while ((read = getline(&line, &len, pf)) != -1) { //firewall rule has any rule exist
						//fprintf(pf2, "%s\n", line);
						fputs(line, pf2);
					}

					fclose(pf);
					fclose(pf2);
					remove(_FW_RULE_NOR_NAME);
					//rename the file firewall_rule.tmp to original name
					rename(_FW_RULE_TMP_NAME, _FW_RULE_NOR_NAME);
					return;
				//fprintf(pf, "%s\n", fw_rule);
			}else{
				printf("Cannot create normal plain text firewall rule name: %s\n", _FW_RULE_TMP_NAME);
				exit(EXIT_FAILURE);
			}
		}
	}else {
		printf("Cannot create normal plain text firewall rule name: %s\n", _FW_RULE_NOR_NAME);
		exit(EXIT_FAILURE);
	}

	fclose(pf);
	return;
}

void write_to_procf(node *fdsd){
	FILE *pf, *pf1;
	pf = fopen(_PROCF_NAME, _O_WRITE);
	pf1 = fopen(_FW_RULE_DSD_NAME, _O_WRITE);
	if (pf == NULL || pf1 == NULL)  {
		printf("Cannot open %s or %s for writing\n", _PROCF_NAME, _FW_RULE_DSD_NAME); //_PROCF_NAME = real , _TEST_NAME = test);
	    return;
	} else {

		node *dest_port, *dest_ip, *src_ip, *proto, *act;
		dest_port = fdsd;
		int count = 1;
		while(dest_port){
			//printf("test ----------> %u, %u\n", dest_port->start, dest_port->stop);
			dest_ip = dest_port->child;
			while(dest_ip){
				src_ip = dest_ip->child;
				while(src_ip){
					proto = src_ip->child;
					while(proto){
						act = proto->child;
						while(act){
							//print firewall rule format for wrting to /proc/FW6
							//printf("No %d: %u, (%u, %u), (%u, %u), (%u, %u), (%u, %u), %u\n",
							//		(count++), act->stop, dest_port->start, dest_port->stop, dest_ip->start, dest_ip->stop,
							//		src_ip->start, src_ip->stop, proto->start, proto->stop, act->start);
							 //show FDSD rules to user space console

							//printf("%u %u %u %s %s %s %s %u %u %u\n", act->stop,
							//		dest_port->start, dest_port->stop,
							//		convert_int_to_IP(dest_ip->start), convert_int_to_IP(dest_ip->stop),
							//		convert_int_to_IP(src_ip->start), convert_int_to_IP(src_ip->stop),
							//		proto->start, proto->stop,
							//		act->start);
							// write FDSD rules to firewall_rule.dsd file in user space
							fprintf(pf1, "%u %u %u %s %s %s %s %u %u %u\n", act->stop,
									dest_port->start, dest_port->stop,
									convert_int_to_IP(dest_ip->start), convert_int_to_IP(dest_ip->stop),
									convert_int_to_IP(src_ip->start), convert_int_to_IP(src_ip->stop),
									proto->start, proto->stop,
									act->start);
							// write FDSD rules to /proc/FW6 file in kernel module space
							fprintf(pf, "%u %u %u %u %u %u %u %u %u %u\n", act->stop,
									dest_port->start, dest_port->stop,
									dest_ip->start, dest_ip->stop,
									src_ip->start, src_ip->stop,
									proto->start, proto->stop,
									act->start);

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
		fprintf(pf, "%c\n", _EOF);
		fprintf(pf1, "%c\n", _EOF);
		fclose(pf);
		fclose(pf1);
	}
	return;
}

void read_from_procf(unsigned char struct_id){
	FILE *pf;
	struct firewall_rule_struct firewall_rule;
	pf = fopen(_PROCF_NAME, _O_READ);
	if (pf == NULL)  {
		printf("Cannot open /proc/minifirewall for reading\n");
	    return;
	} else {
		if(struct_id == _FW_STRUCT){
			fread(&firewall_rule, sizeof(struct firewall_rule_struct), 1, pf);
		}else if(struct_id == _CMD_STRUCT){
			fread(&contr_cmd, sizeof(struct control_command), 1, pf);
		}
		fclose(pf);
	}
	return;
}

void set_hook(unsigned char hook_id){
	if(hook_id == _OUT){
		if(_DEBUG) printf("added NF_IP_LOCAL_OUT hook to firewall_rule\n");
		firewall_rule.hook_id = _NF_IP_LOCAL_OUT;
	}else if(hook_id == _IN){
		if(_DEBUG) printf("added NF_IP_LOCAL_IN hook to firewall_rule\n");
		firewall_rule.hook_id = _NF_IP_LOCAL_IN;
	}else {
		fprintf(stderr, "Bad hook id: should be either --in or --out\n");
	}
	if(_DEBUG) printf("hook id = %u\n", (unsigned char)firewall_rule.hook_id);
	return;
}

void set_x(const char* optarg, unsigned char type){

	//printf("field type = %d\n", type);
	switch(type){
		case _IS_SRC_IP:
			if(validate_ip_or_mask(optarg) == _YES){
				firewall_rule.src_ip = (char *)optarg;
				if(_DEBUG) printf("src ip = %s\n", firewall_rule.src_ip);
				break;
			}else if(!strcmp(_ALL, lowercase(optarg)) || !strcmp(_ANY, lowercase(optarg))){
				firewall_rule.src_ip = _ANY;
				if(_DEBUG) printf("src ip = %s\n", firewall_rule.src_ip);
				break;
			}
			else {
				printf("Unknown src ip address\n");
				exit(EXIT_FAILURE);
				//return _FALSE;
			}

		case _IS_DEST_IP:
			if(validate_ip_or_mask(optarg) == _YES){
				firewall_rule.dest_ip = (char *)optarg;
				if(_DEBUG) printf("dest ip = %s\n", firewall_rule.dest_ip);
				break;
			}else if(!strcmp(_ALL, lowercase(optarg)) || !strcmp(_ANY, lowercase(optarg))){
				firewall_rule.dest_ip = _ANY;
				if(_DEBUG) printf("dest ip = %s\n", firewall_rule.dest_ip);
				break;
			}else {
				printf("Unknown dest ip address\n");
				exit(EXIT_FAILURE);
			}

		case _IS_SRC_MASK:
			if(validate_ip_or_mask(optarg) == _YES){
				firewall_rule.src_netmask = (char *)optarg;
				if(_DEBUG) printf("src netmask = %s\n", firewall_rule.src_netmask);
				break;
			}else if(!strcmp(_ALL, lowercase(optarg)) || !strcmp(_ANY, lowercase(optarg))){
				firewall_rule.src_netmask = _ANY;
				if(_DEBUG) printf("src netmask = %s\n", firewall_rule.src_netmask);
				break;
			}else {
				printf("Unknown src netmask\n");
				exit(EXIT_FAILURE);
			}

		case _IS_DEST_MASK:
			if(validate_ip_or_mask(optarg) == _YES){
				firewall_rule.dest_netmask = (char *)optarg;
				if(_DEBUG) printf("dest netmask = %s\n", firewall_rule.dest_netmask);
				break;
			}else if(!strcmp(_ALL, lowercase(optarg)) || !strcmp(_ANY, lowercase(optarg))){
				firewall_rule.dest_netmask = _ANY;
				if(_DEBUG) printf("dest netmask = %s\n", firewall_rule.dest_netmask);
				break;
			}else {
				printf("Unknown dest netmask\n");
				exit(EXIT_FAILURE);
			}

		case _IS_SRC_PORT:
			if(validate_port(optarg)){
				firewall_rule.src_port = (char *)optarg;
				if(_DEBUG) printf("src port = %s\n", firewall_rule.src_port);
				break;
			}else if(!strcmp(_ALL, lowercase(optarg)) || !strcmp(_ANY, lowercase(optarg))){
				firewall_rule.src_port = _ANY;
				if(_DEBUG) printf("src port = %s\n", firewall_rule.src_port);
				break;
			}else exit(EXIT_FAILURE);

		case _IS_DEST_PORT:
			if(validate_port(optarg)){
				firewall_rule.dest_port = (char *)optarg;
				if(_DEBUG) printf("dest port = %s\n", firewall_rule.dest_port);
				break;
			}else if(!strcmp(_ALL, lowercase(optarg)) || !strcmp(_ANY, lowercase(optarg))){
				firewall_rule.dest_port = _ANY;
				if(_DEBUG) printf("dest port = %s\n", firewall_rule.dest_port);
				break;
			}else exit(EXIT_FAILURE);

		case _IS_PROTO:
			//char *str = lowercase(optarg);
			if (!strcmp(_TCP, lowercase(optarg))){
				firewall_rule.proto = lowercase(optarg);
				if(_DEBUG) printf("protocol = %s\n", firewall_rule.proto);
				break;
			}else if (!strcmp(_UDP, lowercase(optarg))){
				firewall_rule.proto = lowercase(optarg);
				if(_DEBUG) printf("protocol = %s\n", firewall_rule.proto);
				break;
			}else if (!strcmp(_ICMP, lowercase(optarg))){
				firewall_rule.proto = lowercase(optarg);
				if(_DEBUG) printf("protocol = %s\n", firewall_rule.proto);
				break;
			}else if (!strcmp(_ANY, lowercase(optarg)) || !strcmp(_ALL, lowercase(optarg))){
				firewall_rule.proto = _ANY;
				if(_DEBUG) printf("protocol = %s\n", firewall_rule.proto);
				break;
			}else {
				fprintf(stderr, "Bad protocol: %s (should be tcp, udp, icmp and any/all)\n", optarg);
				if(_DEBUG) printf("protocol = %s\n", firewall_rule.proto);
				exit(EXIT_FAILURE);
			}

			break;

		case _IS_ACT:
			if (!strcmp("deny", lowercase(optarg))){
				firewall_rule.action = "deny";
				if(_DEBUG) printf("action = %s\n", firewall_rule.action);
				break;
			}else if (!strcmp("accept", lowercase(optarg))){
				firewall_rule.action = "accept";
				if(_DEBUG) printf("action = %s\n", firewall_rule.action);
				break;
			}else {
				fprintf(stderr, "Bad action: %s (should be deny or accept)\n", optarg);
				if(_DEBUG) printf("action = %s\n", firewall_rule.action);
				exit(EXIT_FAILURE);
			}
			exit(EXIT_FAILURE);

		default: break;
	}

	return;
}

/* return 1 if string contain only digits, else return 0 */
unsigned char valid_digit(char *ip_str)
{
    while (*ip_str) {
        if (*ip_str >= '0' && *ip_str <= '9')
            ++ip_str;
        else
            return _NO;
    }
    return _YES;
}

unsigned char validate_port(const char *optarg){
	while (*optarg){
		if (!isdigit(*optarg))
	         return _NO;
	    else
	         ++optarg;
	   }
	return _YES;
}

/* return 1 if IP string is valid, else return 0 */
unsigned char validate_ip_or_mask(const char *optarg){
    int num;
    int dots = 0;
    char *ptr;

    char *opt;
    opt = malloc(sizeof(char) * strlen(optarg));
    strcpy(opt, optarg);

    if (opt == NULL){
    	free(opt);
    	return _NO;
    }

    ptr = strtok((char *)opt, _DELIM);

    if (ptr == NULL){
    	free(opt);
    	return _NO;
    }

    while (ptr) {
        /* after parsing string, it must contain only digits */
        if (!valid_digit(ptr)){
        	free(opt);
        	return _NO;
        }

        num = atoi(ptr);

        /* check for valid IP */
        if (num >= 0 && num <= 255) {
            /* parse remaining string */
            ptr = strtok(NULL, _DELIM);
            if (ptr != NULL){
            	++dots;
            }
         } else {
        	 free(opt);
        	 return _NO;
         }
    }

    /* valid IP string must contain 3 dots */
    if (dots != 3) {
    	free(opt);
    	return _NO;
    }
    free(opt);
    return _YES;
}

/* convert all characters in arguments to lower case for comparing */
char *lowercase(const char *argv){
	char *str = NULL;
	char *ret = NULL;
	str = (char *)malloc(strlen(argv)+1);
	int length = strlen(argv);
	ret = str;
	str[length] = '\0';
	while(*argv != '\0') {
		*str = tolower(*argv);
		argv++;
		str++;
	}
	return ret;
}

void init_fw(){
	firewall_rule.in_out = -1;
	firewall_rule.src_ip = NULL;
	firewall_rule.src_netmask = NULL;
	firewall_rule.src_port = NULL;
	firewall_rule.dest_ip = NULL;
	firewall_rule.dest_netmask = NULL;
	firewall_rule.dest_port = NULL;
	firewall_rule.proto = NULL;
	firewall_rule.action = NULL;
	firewall_rule.rule_num = 0;
	firewall_rule.packet_count = 0;

}


