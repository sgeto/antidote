/** -*- project-c -*-
 * Simply a few routines to turn error numbers
 * into vaguely intelligible text. Included here because there's
 * nowhere else for them.
 */

#include "antidote.h"

/**
 * Decodes an error number into a sensible human-readable meaning.
 * 
 * \arg errnum - An error number.
 * \arg *result - A buffer in which the result will be stored. This does not
 * need to be previously malloc'ed, as decodeerr will do this.
 */
void decodeerror(int errnum, char *result){
#ifdef STDC_HEADERS
	if (result == NULL){
		return;
	}	
	switch (errnum) {
	case OK : strcpy(result,"OK: Executed successfully.\n"); 
		break; 
		/* PCAP oriented errors */
	case ERR_LOOKUPDEV : strcpy(result,"ERR_LOOKUPDEV: Cannot attach to device.\n");
		break;
	case ERR_OPENLIVE : strcpy(result,"ERR_OPENLIVE: Cannot open device.\n");
		break;
	case ERR_COMPILEBPF : strcpy(result,"ERR_COMPILEBPF: Cannot compile BPF packet filter.\n");
		break;
	case ERR_SETFILTER : strcpy(result,"ERR_SETFILTER: Cannot set BPF packet filter.\n");
		break;
	case ERR_LOOKUPNET : strcpy(result,"ERR_LOOKUPNET: Pcap cannot look up network address.\n");
		break;
		/* Option file errors */
	case ERR_NOOPTSFILE : strcpy(result,"ERR_NOOPTSFILE: Cannot open configuration file.\n");
		break;
	case ERR_INOPTS : strcpy(result,"ERR_INOPTS: Syntax error in configuration file.\n");
		break;
		/* Mail server errors */
	case ERR_CANNOTGETMAILSERVER : strcpy(result,"ERR_CANNOTGETMAILSERVER: Cannot resolve mail server hostname.\n");
		break;
	case ERR_CONNECTMAILSERVER : strcpy(result,"ERR_CONNECTMAILSERVER: Cannot connect to mail server.\n");
		break;
	case ERR_CONNECTCLOSED : strcpy(result,"ERR_CONNECTCLOSED: Connection unexpectedly closed.\n");
		break;
	case ERR_WRONGREPLY: strcpy(result,"ERR_WRONGREPLY: Server returned an unexpected reply.\n"); 
		break;
		/* General errors */
	case ERR_NOMEM : strcpy(result,"ERR_NOMEM: Cannot allocate memory.\n");
		break;
	case ERR_BADUSAGE : strcpy(result,"ERR_BADUSAGE: Function called incorrectly.\n");
		break;
	case ERR_MACCHANGED: strcpy(result,"ERR_MACCHANGED: A MAC address has changed.\n");
		break;
	default: strcpy(result,"ERR_ID10T: Non-existent error code.\n");
		break;
	}
#endif
}
