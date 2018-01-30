/* -*- project-c -*- */
/**
 * \file antidote.h
 * \brief Header descriptions for antidote.
 */

#include "includes.h"
#include "errors.h"

#if ! ETH_ALEN
/* BSD doesn't define this. Don't know about others. */
# define ETH_ALEN 6
#endif

#if ! HAVE_LIBPCAP
# error Libpcap not found. This program requires libpcap version 0.5 or greater.
#endif

#define HIGHEST 1
#define MEDIUM 2
#define LOWEST 3
#define NOTICE 4
#define ADOTE_ERR_BUFF 256
#define MAX_OPT_LENGTH 255

/**
 * Default option values
 * OPTCHARS is used with getopt() to define the allowed options.
 *
 * Currently supported:
 * - -f config file (default /etc/antidote)
 */

#define OPTCHARS "hf:"
#define DEFAULTDEVICE "" 
#define OPTSFILE "/etc/antidote.cfg"
#define SENDER "antidote@localhost"
#define MAILRECIPIENT "root@localhost"
#define MAILSERVER "localhost"
#define MAILPORT 25
#define PROMISCUOUS 1
#define CHECKMACS 1
#define POISON_THRESHOLD 10
#define BADNET_THRESHOLD -10
#define TIMEOUT 1500 /* max seconds details are stored for. */
#define BPF_PROGRAM "arp"
#define PROGNAME "ANTIDOTE"
#define MAX_OPT_LENGTH 255

/**
 * Program options. There are a number of ways of handling this:
 *  - #defined values in this file
 *    - Pros: Easy to implement, easy to change at compile time.
 *    - Cons: Difficult to change at run time.
 *  - An array of options which gets passed around. Options take a fixed
 *    point within this array.
 *    - Pros: Simple, fast.
 *    - Cons: Difficult to handle future option changes whilst retaining
 *      compatability with old versions
 *  - A structure containing options. My favourite, for the following reasons:
 *    - Pros: Easy to implement, easy to add options in future.
 *    - Cons: Will require slightly more processor cycles for implementation,
 *      so it'll be a bit slower.
 *
 * In these days of multi gigahertz processors, a handful of clock cycles for
 * handling options is the least of my worries. So I'm going with the third option.
 *
 * OPTIONS SUPPORTED SHALL INITIALLY BE:
 * settings_file : Location of configuration file
 * root_email : Root's email address.
 * mail_server : Mail server
 * promiscuous : Promiscuous mode
 * poison_threshold : Threshold before alerting to poisoning.
 * badnet_threshold : Threshold before alerting to a dodgy network.
 * timeout : Length of time to store IP details for.
 * check_mac_changes : Check whether an IP address suddenly acquires a new MAC. */
 
struct optiondetails{
	char config_file[MAX_OPT_LENGTH];
        char antidote_email[MAX_OPT_LENGTH];
        char root_email[MAX_OPT_LENGTH]; 
	char mail_server[MAX_OPT_LENGTH];
	char bpf_program[MAX_OPT_LENGTH];
	char device[MAX_OPT_LENGTH]; //just in case you need a 255 character device descriptor....
	unsigned int mail_server_port;
	unsigned char promiscuous; 
	unsigned char check_mac_changes;
        int poison_threshold;
	int badnet_threshold;
	long timeout;
	
};


/**
 * The structure of information as stored
 */
struct ipdetails {
	u_int8_t ip_address[4]; 
	u_int8_t mac_address[ETH_ALEN]; 
	unsigned int requests;
	unsigned int replies;
	long lastreset;
	struct ipdetails *previous;
	struct ipdetails *next;
};

/*
 The Options
*/

extern struct optiondetails options;

/*
 extern struct optiondetails *options;
*/

/*
  ALERT.C
  Only redalert will send an alert over the network. 
*/
void notice(const char *err);
void alert(const char *err);
void bluealert(const char *err);
void redalert(const char *err);
int netalert(const char *err);
void sendalert(int priority, const char *err);
void alertdodgymacs(struct ipdetails *ip_details, u_int8_t *ether_mac);
void alertchangedmacs(struct ipdetails *ip_details, u_int8_t *arp_mac);
void netsend(char *string, int *len, int recipient);
int mailalert(const char *recipient, const char *subject, const char *msg);
int netwait(const char *string, int len, int sender);

/*
 * AUDIT.C
 */

int checknetarps(struct ipdetails *ip);
void checkmacs(struct ipdetails *ipdetails, u_int8_t *ether_mac);
int checkmacchanges(struct ipdetails *ipdetails, u_int8_t *ether_mac);
struct ipdetails *checktimeouts(struct ipdetails *ip);
int sumbytes(u_int8_t *start, int count);

/* HANDLEDATA.C */
struct ipdetails *createipspace();
int addrequest(struct ipdetails *ip);
int addreply(struct ipdetails *ip);
struct ipdetails *searchbackwards(struct ipdetails *startpoint, u_int8_t *ipaddress);
struct ipdetails *searchforwards(struct ipdetails *startpoint, u_int8_t *ipaddress);
struct ipdetails *checkip(struct ipdetails *startpoint, u_int8_t *ipaddress);
int populateipspace(struct ipdetails *ip_space, const u_char *frame);
int populateipspacereq(struct ipdetails *ip_space, const u_char *frame);
int populateipspacerep(struct ipdetails *ip_space, const u_char *frame);
u_int8_t *getipaddress(const char *frame);
void dumpdata(struct ipdetails *entrypoint, char *filename);
void removeip(struct ipdetails *victim);
void blanknetarps(struct ipdetails *ip);
void resettimer(struct ipdetails *ip);

/* ANTIDOTE.C */
int initether(char *devopen);
int handlereply(struct ipdetails **info, const char *frame);
int processether(const u_char *frame);
void processip(struct ipdetails **info);
int handlerequest(struct ipdetails **info, const char *frame);
void showusage(int argc, char **argv);

/*
   OPTIONS.C
*/

int setdefaults();
int readoptions(FILE *optsfile);
int processarguments(int argc, char **argv);
int loadoptions();
int readoptions(FILE *optsfile);
int eatuseless(FILE *filename);
int setoption(char *optname, char *optval);
int getnextvalue(char *buffer, FILE *optsfile);
int getnextname(char *buffer, FILE *optsfile);

/* ERRORS.C */

void decodeerror(int errnum, char *result);
