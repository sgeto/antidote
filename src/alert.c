/* -*- project-c -*-i */
/**
 * \file alert.c
 * \brief Routines for alerting the operator.
 *
 * This module contains routines for alerting the operator to a problem and 
 * logging these alerts.
 *
 * In addition to generalistic alerts of different priorities, this also contains
 * modules for alerts in special situations, where the alert must contain
 * additional detail - such as when an IP address suddenly starts referring
 * to a different MAC. 
 */

#include "antidote.h"

/**
 * A wrapper around the alert functions, if you'd rather use a single
 * function which allows you to specify priority... 
 *
 * ARGUMENTS:
 * \arg \c priority - An integer representation of the priority. This should be 
 * taken from antidote.h, and be one of HIGHEST, MEDIUM, LOWEST or NOTICE.
 * \arg \c *err - A pointer to a null-terminated string containing the message to
 * be sent.
 */
void sendalert(int priority, const char *err){
	switch (priority) {
	case HIGHEST: redalert(err);
		break;
	case MEDIUM: bluealert(err);
		break;
	case LOWEST: alert(err);
		break;
	case NOTICE: notice(err);
		break;  
	}
}

/**
 * Basic, unimportant notices
 */
void notice(const char *err){
#if HAVE_SYSLOG_H
	openlog(PROGNAME, (int) NULL, LOG_USER);
	syslog(LOG_INFO, "Message: %s", err);
	closelog();
#else
	printf(stderr,"Message from %s: %s", PROGNAME, err);
#endif
}

/**
 * Alert when an IP address has a different MAC to that previously logged.
 *
 * \note This routine does not check that the details it has been received are
 * genuinely indicitave of a changed MAC. Therefore, bugs elsewhere in the code
 * can cause it to announce that a machine has acquired a new MAC and then proudly
 * display two identical MACs as the previous and new MACs.
 *
 * ARGUMENTS:
 * \arg \c *ip_details - A pointer to a structure defining the IP address and other details for
 * the machine with the new MAC.
 * \arg \c *arp_mac - A pointer to an array of 8 bit unsigned integers holding the new MAC address. 
 */
void alertchangedmacs(struct ipdetails *ip_details, u_int8_t *arp_mac){
	char *err, *err2;
	int lp;
	err = malloc(ADOTE_ERR_BUFF);
	err2 = malloc(ADOTE_ERR_BUFF);

	if (err != NULL){
		sprintf(err, "%d.%d.%d.%d has different MAC details. ", ip_details->ip_address[0], ip_details->ip_address[1], ip_details->ip_address[2], ip_details->ip_address[3]);
	
		if (err2 != NULL) {
			strcat(err, " Previous MAC: ");
			for (lp = 0; lp <= ETH_ALEN-1; lp++){
				sprintf(err2, "%X", ip_details->mac_address[lp]);
				strcat(err, err2);
				if (lp < ETH_ALEN-1)
					strcat(err, ":");
			}
		        strcat(err, " New MAC: ");
			for (lp = 0; lp <= ETH_ALEN-1; lp++){
				sprintf(err2, "%X", arp_mac[lp]);
				strcat(err, err2);
				if (lp < ETH_ALEN-1)
					strcat(err, ":");
			}
		}
		redalert(err);
	}else{
		redalert("A machine appears to have changed MAC details. Insufficient memory to give full information.");
	}
	free(err);
	free(err2);
}

/**
 * Special case alert for if the MAC in the Ethernet frame and the MAC in the ARP packet
 * do not match. 
 * \note In theory this should be impossible, however, if a potential hacker
 * is using an operating system which does not allow forging MACs at the Ethernet frame
 * level (or just omits forging this), this may be the first warning the operator gets 
 * of something amiss.
 *
 * ARGUMENTS:
 * \arg \c *ip_details - A pointer to the structure containing the information for the 
 * offending machine.
 * \arg \c *arp_mac - A pointer to an array of unsigned 8 bit integers containing it's
 * "alternative" MAC address.
 */
void alertdodgymacs(struct ipdetails *ip_details, u_int8_t *arp_mac){
/* I'm sorry, but...
 * ALERT: SOMEONE IS WEARING AN ANORAK!
 */

	char *err, *err2;
	int lp;
	err = malloc(ADOTE_ERR_BUFF);
	err2 = malloc(ADOTE_ERR_BUFF);
	if (err != NULL){
		sprintf(err, "%d.%d.%d.%d gives conflicting MAC details. ", ip_details->ip_address[0], ip_details->ip_address[1], ip_details->ip_address[2], ip_details->ip_address[3]);
	
		if (err2 != NULL) {
			strcat(err, " Ethernet MAC: ");
			for (lp = 0; lp <= ETH_ALEN-1; lp++){
				sprintf(err2, "%X", ip_details->mac_address[lp]);
				strcat(err, err2);
				if (lp < ETH_ALEN-1)
					strcat(err, ":");
			}
		        strcat(err, " ARP body MAC: ");
			for (lp = 0; lp <= ETH_ALEN-1; lp++){
				sprintf(err2, "%X", arp_mac[lp]);
				strcat(err, err2);
				if (lp < ETH_ALEN-1)
					strcat(err, ":");
			}
		}
		redalert(err);
	}else{
		redalert("A machine appears to be giving conflicting MAC details. Insufficient memory to give full information.");
	}
	free(err);
	free(err2);
}

/**
 * A mildly important alert.
 */
void alert(const char *err){
#if HAVE_SYSLOG_H
	openlog(PROGNAME, LOG_PERROR, LOG_USER);
	syslog(LOG_INFO, "Message: %s", err);
	closelog();
#else
	printf(stderr,"Alert from %s: %s", PROGNAME, err);
#endif 
}

/**
 * An important alert.
 */
void bluealert(const char *err) {
#if HAVE_SYSLOG_H
	int ALERT = LOG_CONS | LOG_PERROR; 
	openlog(PROGNAME, ALERT, LOG_USER);
	syslog(LOG_ERR, "Error: %s", err);
	closelog();
#else
	printf(stderr,"Important Alert from %s: %s", PROGNAME, err);
#endif
}

/**
 * A highly important "Dear God Someone's Brought Down The Entire Network" alert.
 * Do not use lightly! 
 */
void redalert(const char *err){
#if HAVE_SYSLOG_H
	int ALERT = LOG_CONS | LOG_PERROR;
	openlog(PROGNAME, ALERT, LOG_AUTHPRIV);
	syslog(LOG_CRIT, "URGENT ALERT FROM %s: %s\n", PROGNAME, err);
	closelog();
#else
	printf(stderr,"URGENT ALERT FROM %s: %s", PROGNAME, err);
#endif
	netalert(err);
}

/**
 * Network alerting. For now, I'm just going to send an email alert. There are
 * are a number of arguments for and against this, briefly:
 * FOR: 
 *  - Simple, easy to implement.
 *  - Most modern networks will have access to an SMTP gateway.
 *  - (Hopefully) most administrators will have an email account which they
 *    read reasonably regularly. I imagine that those who do not will
 *    not be using this program anyway, as they're probably unaware what
 *    happens when information is sent across their network. Hello MCSE's.
 *  - The obvious alternative is to devise an alerting protocol which 
 *    is broadcast,  and write a program to spot such alerts. This 
 *    adds considerably to the complication. Alternatively, one could
 *    possibly use SNMP, but I've got absolutely no idea how that works.
 *    Besides, this is aimed at smaller networks without the cash or need to
 *    implement complex solutions, and there are few cheap half-decent SNMP
 *    solutions that I'm aware of. Changing this is left for future 
 *    generations.
 * AGAINST:
 *  - Since it's using cooked sockets, it's vulnerable to the very man in the
 *    middle attacks it's supposed to alert about. 
 *  - That being said, if anyone is moronic enough to intercept an SMTP
 *    server (on which it's pretty unlikely any passwords will be sent) the
 *    chances of detection via other means (I CAN'T SEND ANY EMAIL!! HELP!!)
 *    are pretty high.
 */
int netalert(const char *err) {
	int error;
	if (options.root_email != "NO") {
		error = mailalert(options.root_email, "Network Alert from Antidote", err);
		switch (error) {
		case ERR_NOMEM: 
#if HAVE_SYSLOG_H
			openlog(PROGNAME, LOG_PERROR, LOG_AUTHPRIV);
			syslog(LOG_ERR, "Insufficient memory to send email alert.");
			closelog();
#else
			printf(stderr, "Insufficient memory to send email alert.");
#endif
			break;
		case ERR_CANNOTGETMAILSERVER: 
#if HAVE_SYSLOG_H
			openlog(PROGNAME, LOG_PERROR, LOG_AUTHPRIV);
			syslog(LOG_ERR, "Cannot contact mail server.");
			closelog();
#else
			printf(stderr, "Cannot contact mail server.");
#endif
			break;
	       
		case ERR_CONNECTCLOSED: 
#if HAVE_SYSLOG_H
			openlog(PROGNAME, LOG_PERROR, LOG_AUTHPRIV);
			syslog(LOG_ERR, "Connection to mail server unexpectedly closed.");
			closelog();
#else
			printf(stderr, "Connection to mail server unexpectedly closed.");
#endif
			break;
		
		case ERR_WRONGREPLY:
#if HAVE_SYSLOG_H
			openlog(PROGNAME, LOG_PERROR, LOG_AUTHPRIV);
			syslog(LOG_ERR, "Mail server sent unrecognised reply.");
			closelog();
#else
			printf(stderr, "Mail server sent unrecognised reply.");
#endif
			break;
		
		}
	}
	return 0;
}

/**
 * Sends an emailed alert to a specific address.
 *
 * I haven't used lib(e)smtp for 2 reasons - I don't think
 * that many installations include it as standard, and it's a long
 * way from being a stable API. (So is libpcap, but I'd like to keep
 * such problems to a minimum).
 *
 * SMTP in brief:
 *
 * SENDER: HELO <domain><CRLF>
 * RECIPIENT: 250 OK, hi there.
 * S: MAIL FROM:<reverse-path><CRLF>
 * R: 250 OK
 * S: RCPT TO:<forward-path><CRLF>
 * R: 250 OK (550 if no such recipient)
 * \note Should also accept 251 (User not local), 
 * S: DATA<CRLF>
 * R: 354 Give it to me baby, uh huh uh huh...
 * S: <data... includes Subject, To:, From: etc etc...>
 * S: <CRLF>.<CRLF>
 * R: 250 OK
 * S: QUIT
 * R: 221 Cheerio. 
 *
 * \todo Learn socket programming!
 */


int mailalert(const char *recipient, const char *subject, const char *msg){
/**
 * Will someone please tell me what I was drinking when I wrote this?!
 *
 * All those of you who have just found a bug in gdb, raise your hands.
 */
#if HAVE_SOCKET
	int mailserver, bufsize, errcode;
	char *buf, *hostname, *timestr;	  
	time_t currenttime;
	struct hostent *mailserver_ip;
	struct sockaddr_in destination;
	if ((buf = (char *)malloc(ADOTE_ERR_BUFF+10)) == NULL)
		return ERR_NOMEM;
	if ((hostname = (char *)malloc(ADOTE_ERR_BUFF)) == NULL){
		free(buf);
		return ERR_NOMEM;
	}
	if ((timestr = (char *)malloc(ADOTE_ERR_BUFF)) == NULL){
		free(buf);
		free(hostname);
		return ERR_NOMEM;
	}    
	mailserver = socket(AF_INET, SOCK_STREAM, 0);
	destination.sin_family = AF_INET;
	destination.sin_port = htons(options.mail_server_port);
#if HAVE_GETHOSTNAME
	if (gethostname(hostname, ADOTE_ERR_BUFF) != 0)
#endif
	        strcpy(hostname, "localhost.localdomain");
	if ((mailserver_ip = gethostbyname(options.mail_server)) == NULL){
		free(buf);
		free(hostname);
		free(timestr);
		return ERR_CANNOTGETMAILSERVER;
	}
        destination.sin_addr = *((struct in_addr *)mailserver_ip->h_addr);
	memset(&(destination.sin_zero), '\0', 8);
	if (connect(mailserver, (struct sockaddr *)&destination, sizeof(struct sockaddr)) == -1){
		free(buf);
		free(hostname);
		free(timestr);
		return ERR_CONNECTMAILSERVER;
	}	
	if ((errcode = netwait("220", 3, mailserver)) != OK){	
		free(buf);
		free(hostname);
		free(timestr);
		return errcode;
	}
	bufsize = sprintf(buf, "HELO %s\r\n", hostname);
	netsend(buf, &bufsize, mailserver);
	if ((errcode = netwait("250", 3, mailserver)) != OK){
		free(buf);
		free(hostname);
		free(timestr);
		return errcode;
	}
	bufsize = sprintf(buf, "MAIL FROM:%s\r\n", options.antidote_email);
	netsend(buf, &bufsize, mailserver);
	if ((errcode = netwait("250", 3, mailserver)) != OK){
		free(buf);
		free(hostname);
		free(timestr);
		return errcode;
	}
	bufsize = sprintf(buf, "RCPT TO:%s\r\n", recipient);
	netsend(buf, &bufsize, mailserver);	
	if ((errcode = netwait("250", 3, mailserver)) != OK){
		free(buf);
		free(hostname);
		free(timestr);
		return errcode;
	}
	bufsize = sprintf(buf, "DATA\r\n");
	netsend(buf, &bufsize, mailserver);
	if ((errcode = netwait("354", 3, mailserver)) != OK){
		free(buf);
		free(hostname);
		free(timestr);
		return errcode;
	}
	time(&currenttime);
        timestr = ctime(&currenttime);
	bufsize = sprintf(buf, "Date: %s\r\n", timestr);
	netsend(buf, &bufsize, mailserver);    
	bufsize = sprintf(buf, "From: %s\r\n", options.antidote_email);
	netsend(buf, &bufsize, mailserver);
	bufsize = sprintf(buf, "Subject: %s\r\n", subject);
	netsend(buf, &bufsize, mailserver);	
	bufsize = sprintf(buf, "To: %s\r\n", recipient);
	netsend(buf, &bufsize, mailserver);
	bufsize = sprintf(buf, "%s\r\n.\r\n", msg); // Is this safe or is it subject to a buffer overflow?
	netsend(buf, &bufsize, mailserver);
	if ((errcode = netwait("250", 3, mailserver)) != OK){
		free(buf);
		free(hostname);
		free(timestr);
		return errcode;
	}
	bufsize = sprintf(buf, "QUIT\r\n");
	netsend(buf, &bufsize, mailserver);
	if ((errcode = netwait("221", 3, mailserver)) != OK){
		free(buf);
		free(hostname);
		free(timestr);
		return errcode;
	}
	close(mailserver);
#endif
	return OK;
}

/**
 * Waits for the next transmission from a sender, compares it to *string and
 * if the two are the same returns OK, otherwise:
 *
 * ARGUMENTS:
 * \arg \c *string - Comparator
 * \arg \c len - Number of bytes to compare
 * \arg \c sender - Socket on which the data will be coming in.
 *
 * RETURN VALUES:
 * \return ERR_CONNECTCLOSED - Connection closed by foreign host
 * \return ERR_WRONGREPLY - Wrong reply received.
 */
int netwait(const char *string, int len, int sender){
	char buffer[ADOTE_ERR_BUFF];
	int bytesrcvd;
	bytesrcvd = recv(sender, buffer, ADOTE_ERR_BUFF, 0);
	if (bytesrcvd  == 0)
		return ERR_CONNECTCLOSED;
	if (bytesrcvd < len)
		return ERR_WRONGREPLY;
	if (strncmp(string, buffer, len) == 0)
		return OK;
	return ERR_WRONGREPLY;	
}

/**
 * Send a string to a network recipient.
 * Arguments:
 * *string - pointer to a string to send.
 * *len - length of the string.
 * recipient - a socket descriptor of the recipient.
 */
void netsend(char *string, int *len, int recipient){
	int total = 0, bytesleft = *len, bytessent;
	while (total < *len) {
		bytessent = send(recipient, string+total, bytesleft, 0);
		if (bytessent == -1) 
			break;
		total += bytessent;
		bytesleft -= bytessent;
	}
}
