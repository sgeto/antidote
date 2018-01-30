/* -*- project-c -*- */

/**
 * \file checkopts.c
 * \brief Loading and parsing program options, both from command line 
 * and from config file.
 *
 */

#include "errors.h"
#include "antidote.h"

/**
 * We need routines that will:
 * - Open an options file for reading
 * - Read it in, a line at a time, and place the options into our option
 * structure.
 * - A frontend which literally just takes the command line options, a
 * pointer which we can set to point at the options structure and... erm.
 * that's it.
 *
 * Okay, first thing's first - we need to know which options file, so our
 * functions could be prototyped as:
 *
 * int readoptions(const char *filename, struct *options);
 * struct options *frontend(char **argv, int argc);
 * 
 * frontend() requires getopts, which I don't have ATM. So it can wait.
 */


/**
 * I'd just like to say that this is the first global variable I've
 * used since the days of BASIC.
 *
 * I was half expecting to be struck down by lightning on typing it. As it is,
 * I merely got a slight static shock.
 */
struct optiondetails options;

/**
 * Set default options.
 * struct optiondetails{
 *	char config_file;
 *      char antidote_email;
 *	char root_email;  // set to NO if you don't want email alerts.
 *      char mail_server;
 *      char bpf_program;   - This makes it very easy to change what we filter.
 *	unsigned int mail_server_port;
 *	unsigned char promiscuous; 
 *	unsigned char check_mac_changes;
 *      int poison_threshold;
 *	int badnet_threshold;
 *	long timeout;
 *};
 */

int setdefaults(){	
/**
 * Compiler directives storing strings are evidently referenced as pointers,
 * which is all well and good. What isn't so good is I want to copy their
 * contents into the options structure.
 *
 */	
	strcpy(options.config_file, OPTSFILE);
	strcpy(options.antidote_email, SENDER);
	strcpy(options.root_email, MAILRECIPIENT);
	strcpy(options.mail_server, MAILSERVER);
	options.mail_server_port = MAILPORT;
	strcpy(options.device, DEFAULTDEVICE);
	strcpy(options.bpf_program, BPF_PROGRAM);
	options.promiscuous = PROMISCUOUS;
	options.check_mac_changes = CHECKMACS;
	options.poison_threshold = POISON_THRESHOLD;
	options.badnet_threshold = BADNET_THRESHOLD;
	options.timeout = TIMEOUT;
	return OK;
}

/**
 * Loads the options into memory
 */
int loadoptions(){
	FILE *optsfile;
      	int result = OK;
	setdefaults(); /* in case the opts file is being reloaded and a setting has been removed.  */     
	if ((optsfile = fopen(options.config_file, "r")) == NULL){
		bluealert("No options file detected - using defaults. This is probably not what you want!");
		result = ERR_NOOPTSFILE;
	} else {
		result = readoptions(optsfile);
		fclose(optsfile);
	}
	return result;
}

/**
 * Read / parse the options file.
 * Hmmm.
 *
 * This one's actually quite tough. Given that the format of the options file is relatively
 * loosely defined, this code becomes rather tricky.
 *
 * I'm going to borrow a line from Eric S. Raymond (The Cathedral and the Bazaar) and
 * make the data structure smart and the code dumb.
 *
 * Specifically, I'm going to write the grammar of the options file.
 *
 */
int readoptions(FILE *optsfile){
	int result = OK;
	char *optname, *optval;
	optname = (char *)malloc(sizeof(char) * MAX_OPT_LENGTH);
	optval = (char *)malloc(sizeof(char) * MAX_OPT_LENGTH);
	if ((optname == NULL) || (optval == NULL))
		result = ERR_NOMEM;
	while (result == OK){ 
		result = eatuseless(optsfile);
		if (result == OK)
			result = getnextname(optname, optsfile);
		if (result == OK)
			result = eatuseless(optsfile);
		if (result == OK)
			result = getnextvalue(optval, optsfile);
		if (result == OK)
			result = setoption(optname, optval);
	} 
	free(optname);
	free(optval);
	return result;
}

int eatuseless(FILE *filename) {
/**
 * Eats all characters in a given file which are to be ignored, and sets
 * the file pointer to the next "interesting" character.
 *
 * Returns ERR_EOF if the file ends before an "interesting" character is found.
 */
	char temp;
	int result = OK, finished = 0, comment = 0;
	while (finished == 0){
		temp = fgetc(filename);
		/* We can continue if we've hit a space, a # or anything (if we're in a comment) */
		if (comment == 0){
/**
 * isspace(c) returns 0 if c is not a space, nonzero if it is
 */
		       if (isspace(temp) == 0){
			       if (temp == '#')
				       comment = 1;
			       else if (temp != '=')
				       finished = 1;
		       }
		} else {
			if ((temp == '\r')||(temp == '\n'))
				comment = 0;
		}
	}
	if (temp == EOF)
		result = ERR_EOF;
	else
		if (fseek(filename, -1, SEEK_CUR) != 0) 
			result = ERR_INOPTS;
	return result;
}

int setoption(char *optname, char *optval){
	int result = OK;
/**
 * I really wish C supported switch([string])....
 */
	if (strcasecmp(optname, "ethernetdevice") == 0){
		memset(options.device, '\0', (sizeof(char) * sizeof(options.device)));
		strcpy(options.device, optval); 
	} else if (strcasecmp(optname, "emailsender") == 0){
		memset(options.antidote_email, '\0', (sizeof(char) * sizeof(options.antidote_email)));
		strcpy(options.antidote_email, optval);
	} else if (strcasecmp(optname, "emailrecipient") == 0){
		memset(options.root_email, '\0', (sizeof(char) * sizeof(options.root_email)));
		strcpy(options.root_email, optval);
	} else if (strcasecmp(optname, "emailserver") == 0) {
		memset(options.mail_server, '\0',(sizeof(char) * sizeof(options.mail_server)));
		strcpy(options.mail_server, optval);
	} else if (strcasecmp(optname, "emailserverport") == 0) {
		options.mail_server_port = (unsigned int)atoi(optval);
	} else if (strcasecmp(optname, "promiscuous") == 0) {
		if (strcasecmp(optval, "yes") == 0){
			options.promiscuous = 1;
		}else if (strcasecmp(optval, "no") == 0){
			options.promiscuous = 0;
		} else
			result = ERR_INOPTS;				     
	} else if (strcasecmp(optname, "checkmacchanges") == 0) {
		if (strcasecmp(optval, "yes") == 0){
			options.check_mac_changes = 1;
		}else if (strcasecmp(optval, "no") == 0){
			options.check_mac_changes = 0;
		} else
			result = ERR_INOPTS;		
	} else if (strcasecmp(optname, "poisonthreshold") == 0) {
		options.poison_threshold = atoi(optval);
	} else if (strcasecmp(optname, "badnetthreshold") == 0) {
		options.badnet_threshold = atoi(optval);
	} else if (strcasecmp(optname, "timeout") == 0) {
		options.timeout = 60 * (atol(optval));
	}
	return result;
}


int getnextvalue(char *buffer, FILE *optsfile) {
/**
 * Virtually identical to getnextname(), except this does not
 * consider an equals sign to represent the end of the string.
 */
	int length = 0, result = OK;
	char temp, finished = 0;
	if (buffer == NULL)
		buffer = (char *)malloc(sizeof(char) * MAX_OPT_LENGTH);
	if (buffer == NULL)
		result = ERR_NOMEM;
	while ((finished == 0) && (result == OK)){ /* Get option name. */
		temp = fgetc(optsfile);      
		if (length < MAX_OPT_LENGTH) {
			buffer[length] = temp;
			if (isspace(temp)){ 
				buffer[length] = '\0';
				finished = 1;				
			}
		} else {
			finished = 1; 
			result = ERR_INOPTS;
		}
		length++;
	}
	/* buffer (hopefully) now holds the option name */
	return result;
}

int getnextname(char *buffer, FILE *optsfile) {
	int length = 0, result = OK;
	char temp, finished = 0;
	if (buffer == NULL)
		buffer = (char *)malloc(sizeof(char) * MAX_OPT_LENGTH);
	if (buffer == NULL)
		result = ERR_NOMEM;
	while ((finished == 0) && (result == OK)){ /* Get option name. */
		temp = fgetc(optsfile);      
		if (length < MAX_OPT_LENGTH) {
			buffer[length] = temp;
			if ((isspace(temp)) || (temp == '=')){ 
				buffer[length] = '\0';
				finished = 1;				
			}
		} else {
			finished = 1; 
			result = ERR_INOPTS;
		}
		length++;
	}
	/* buffer (hopefully) now holds the option name */
	return result;
}



int processarguments(int argc, char **argv){
	int option, result = OK;
	while ((option != -1) && (result == OK)){
		option = getopt(argc, argv, OPTCHARS);
		switch (option){
		case 'h': showusage(argc, argv);
			result = ERR_INOPTS;
			break;
		case 'f': memset(options.config_file, '\0', sizeof(options.config_file)); 
			strcpy(options.config_file, optarg);
			result = OK;
			break;
		case -1:result = OK; 
			break;
		default: showusage(argc, argv);
			result = ERR_INOPTS;
			break;
		}
	} 
	return result;
}
