/* -*- project-c -*- */
/**
 * \file handledata.c
 * \brief Handling stored information - IP addresses, replies & requests.
 *
 * This module contains routines for handling the information which the 
 * program stores: specifically, IP addresses, replies and requests.
 *
 */

#include "antidote.h"

/** 
 * \return Returns a pointer to a memory space suitable for
 * storing an ipdetails structure.
 * 
 * Automatically fills in the lastreset value at the same time.
 */
struct ipdetails *createipspace() {
	struct ipdetails *result;
	struct timeval *timer;
	timer = malloc(sizeof(struct timeval));
	if (timer == NULL)
		return NULL;
	result = calloc(1, sizeof(struct ipdetails));
	if (gettimeofday(timer, NULL) == 0)
		result->lastreset = timer->tv_sec;
	free(timer);
	return result;
}

/**
 * Pull the IP address from a frame and return a pointer to it.
 * \return Returns a null pointer if handed a null frame.
 */
u_int8_t *getipaddress(const char *frame){
	struct ether_arp *arpbody;
	u_int8_t *ipaddress;
        int lp;
	ipaddress = malloc(4);
	if ((frame != NULL) && (ipaddress != NULL)){
		frame += sizeof(struct ether_header);
		arpbody = (struct ether_arp *) frame;
		for (lp = 0; lp <= 3; lp++){
			ipaddress[lp] = arpbody->arp_spa[lp];
		}
		return ipaddress;
	}else{
		return NULL;
	}
}

/**
 * Populates a given IP space with data from a given frame, first checking
 * to see if it's an ARP reply or a request.
 */
int populateipspace(struct ipdetails *ip_space, const u_char *frame){
	u_int16_t temp;
	int result = ERR_BADUSAGE;
	struct arphdr *arpheader;
	if ((arpheader = (struct arphdr *)malloc(sizeof(struct arphdr))) == NULL)
		return ERR_NOMEM;
	frame += sizeof(struct ether_header);
	arpheader = (struct arphdr *) frame;
	frame -= sizeof(struct ether_header); /* AAARGH! */
	temp = (u_int16_t)arpheader->ar_op;
	temp = ntohs(temp);
	switch (temp){
	case (ARPOP_REQUEST): result = populateipspacereq(ip_space, frame);
		break;
	case (ARPOP_REPLY): result = populateipspacerep(ip_space, frame);
		break;
	}
	return result;
}
/**
 * Populates a given IP space with data from the given ethernet frame.
 * Should correctly fill everything which it reasonably can in.
 *
 * This routine is used if the IP space is being filled with details taken 
 * from an ARP request : for a routine for details coming from an ARP reply,
 * see populateipspacerep(). For a generic wrapper which decides which 
 * routine to use, see populateipspace().
 *
 * Does not link with other ipspaces or affect any other details.
 *
 * Does check that MACS in header & ARP packet tally.
 *
 * WHEN LOOKING AT A REQUEST, WE FILE ACCORDING TO RECIPIENT.
 */
int populateipspacereq(struct ipdetails *ip_space, const u_char *frame){
	struct ether_arp *arpbody;
	struct ether_header *etherhead;
	int lp;
	if ((ip_space == NULL) || (frame == NULL))
		return ERR_BADUSAGE;
	etherhead = (struct ether_header *) frame;
	frame += sizeof(struct ether_header);
	arpbody = (struct ether_arp *) frame;
	for (lp = 0; lp <= 3; lp++) {
	        ip_space->ip_address[lp] = arpbody->arp_tpa[lp];	      
	}
	/*
	 * If it's a request, we are less likely to have the recipients MAC
	 *
	 * We therefore remove the line which fills these details in
	 *
 	 * for (lp = 0; lp <= ETH_ALEN; lp++) {
	 *	ip_space->mac_address[lp] = etherhead->ether_dhost[lp];
	 *}
	 */

/*	checkmacs(ip_space, arpbody->arp_tha);*/
/* we don't bother checking that MACs tally with ARP requests, only replies. Forged requests are less likely 
   with requests */
	
	return OK;
}
/**
 * Populates a given IP space with data from the given ethernet frame.
 * Should correctly fill everything which it reasonably can in.
 *
 * Does not link with other ipspaces or affect any other details.
 *
 * Does check that MACS in header & ARP packet
 *
 * WHEN LOOKING AT A REPLY, WE FILE ACCORDING TO SENDER.
 */
int populateipspacerep(struct ipdetails *ip_space, const u_char *frame){
	struct ether_arp *arpbody;
	struct ether_header *etherhead;
	int lp;
	if ((ip_space == NULL) || (frame == NULL))
		return ERR_BADUSAGE;
	etherhead = (struct ether_header *) frame;
	frame += sizeof(struct ether_header);
	arpbody = (struct ether_arp *) frame;
	for (lp = 0; lp <= 3; lp++) {
	        ip_space->ip_address[lp] = arpbody->arp_spa[lp];	      
	}
	for (lp = 0; lp <= ETH_ALEN; lp++) {
		ip_space->mac_address[lp] = etherhead->ether_shost[lp];
	}
	checkmacs(ip_space, arpbody->arp_sha);
	return OK;
}

/**
 * Add 1 to the request field for a specified IP
 *
 * Ideally I'd like to be able to do this by specifying an IP address rather 
 * than a data structure. However, since we have a routine to find the structure
 * belonging to a specific IP, it's not really necessary.
 *
 * Admittedly, this routine is perhaps appplying object-oriented
 * ideals to top-down code, however, if the programmer only ever uses this routine
 * to alter the request field, we should be able to guarantee that it never holds
 * a silly value.
 *
 * And for my next trick I shall walk on the moon.
 */
int addrequest(struct ipdetails *ip){
	if (ip == NULL)
		return (int)NULL;
	ip->requests++;
	return ip->requests;
}

/**
 * Add 1 to the reply field for a specified IP.
 * See also: addrequest(struct ipdetails *ip)
 */
int addreply(struct ipdetails *ip){
	if (ip == NULL)
		return (int)NULL;
	ip->replies++;
	return ip->replies;
}

/**
 * Search a given list forwards (ie. only following the ipdetails->next pointer)
 * for a specific IP.
 * \return Returns NULL if the item is not found, otherwise returns the address at which
 * the item occurs.
 */
struct ipdetails *searchforwards(struct ipdetails *startpoint, u_int8_t *ipaddress) {
	if (startpoint == NULL) 
		return NULL;
	if (startpoint->ip_address[0] == *(ipaddress)\
			&& (startpoint->ip_address[1] == *(ipaddress+1))\
			&& (startpoint->ip_address[2] == *(ipaddress+2))\
			&& (startpoint->ip_address[3] == *(ipaddress+3))){
		// we've got it!
		return startpoint;
	}
	else 
		return searchforwards(startpoint->next, ipaddress);
	
}

/**
 * Search a given list backwards for a specific IP. Returns NULL if the
 * item is not found.
 *
 * Identical to searchforwards(), except the direction it goes in.
 * And the fact that I'm an idiot.
 */
struct ipdetails *searchbackwards(struct ipdetails *startpoint, u_int8_t *ipaddress) {
	if (startpoint == NULL) 
		return NULL;
	if (startpoint->ip_address[0] == *(ipaddress)\
			&& (startpoint->ip_address[1] == *(ipaddress+1))\
			&& (startpoint->ip_address[2] == *(ipaddress+2))\
			&& (startpoint->ip_address[3] == *(ipaddress+3))){
		// we've got it!
		return startpoint;
	}
	else 
		return searchbackwards(startpoint->previous, ipaddress);
	
}

/**
 * Check to see whether or not a record for a given IP already exists.
 * Return a pointer to it if it does, otherwise return NULL.
 *
 * In terms of complexity, it makes virtually no difference where
 * in the list we start searching. However, in the case of this program,
 * there is a reasonably high probability that our entry point is
 * the item we want to find. Rewinding the list to the beginning would
 * make things a little slower as the rewinding would take some time.
 * It also means that, if we are given a pointer to somewhere in the
 * middle of the list, we may be better off searching inside out rather
 * than from beginning to end.
 *
 * This routine is quite broken up - with any luck, this will make
 * multi-threading the app relatively easy in future.
 */
	
struct ipdetails *checkip(struct ipdetails *startpoint, u_int8_t *ipaddress){	
	struct ipdetails *searchagain;
	if (startpoint == NULL || ipaddress == NULL)
		return NULL; /* No such position */
	if ((*ipaddress == startpoint->ip_address[0])\
			&& (*(ipaddress+1) == startpoint->ip_address[1])\
			&& (*(ipaddress+2) == startpoint->ip_address[2])\
			&& (*(ipaddress+3) == startpoint->ip_address[3]))
	{
		return startpoint; /* item given is the correct item. */
	} else {
		/* likely to get a list near the end, so search forwards first. Should
		 be quicker. */
		searchagain = searchforwards(startpoint->next, ipaddress);
		/* search the next item(s) in the list */
		if (searchagain == NULL)
			searchagain = searchbackwards(startpoint->previous, ipaddress);
		return searchagain;
	}
}

/**
 * Take us to a known IP in the linked list - specifically, the first one.
 * While it's theoretically a wholly unnecessary function (we can always find
 * every item in the list anyway, so why bother going to a specific point?)
 * it makes coding the search for an item somewhat easier, it also makes the code
 * for that kind of thing easier to read - you don't have to think of
 * two things going on at once. (searching in 2 directions)
 */
struct ipdetails *rewindip(struct ipdetails *ip){
	while (ip->previous != NULL){
		ip = ip->previous;
	}
	return ip;
}

/**
 * added for debugging - dumps internal data to a CSV file specified by *filename.
 */
void dumpdata(struct ipdetails *entrypoint, char *filename){
	struct ipdetails *current;
	FILE *dumpfile;
	int lp;
	dumpfile = fopen(filename, "w");
	current = rewindip(entrypoint);
	if (dumpfile != NULL){
		fprintf(dumpfile, "\"IP Address\",\"MAC Address\",\"Requests\",\"Replies\",\"Last Reset\"\n");
		while (current != NULL){
		/** 
		 * Format of a CSV is dead simple:
		 * <data>,[<data>, .....] <CR> 
		 * <data>...............
		 *
		 * I don't believe it. A file format wich can be expressed in 2 lines and
		 * I still ballsed it up.
		 */
			fprintf(dumpfile, "%d.%d.%d.%d,",current->ip_address[0],current->ip_address[1],current->ip_address[2],current->ip_address[3]);
			for (lp = 0; lp < ETH_ALEN; lp++){
				fprintf(dumpfile, "%0X:", current->mac_address[lp]);
			}
			//fprintf(dumpfile, "%X,", current->mac_address[lp+1]);
			fprintf(dumpfile, "%d,%d,%ld\n", current->requests, current->replies, current->lastreset); 
			current = current->next; 
		}
		fclose(dumpfile);
	}
}

/**
 * Remove IP details from the data structure.
 *
 * WARNING: THIS ROUTINE DOES NOT RETURN A POINTER BACK INTO THE STRUCTURE, AND SETS
 * ITS ARGUMENT TO NULL. IF YOU NEED TO RETAIN AN ENTRY POINT TO THE DATA STRUCTURE,
 * CREATE ANOTHER POINT BEFORE CALLING THIS ROUTINE.
 */
/*
void removeip(struct ipdetails *victim) {
	struct ipdetails *before, *after;
	before = victim->previous;
	after = victim->next;
	if (before)
		before->next = victim->next;
	if (after)
		after->previous = victim->previous;
	free(victim);
}
*/

void resettimer(struct ipdetails *ip){
	struct timeval *timer;
	timer = malloc(sizeof(struct timeval));
	if (timer == NULL)
		return;
	if (gettimeofday(timer, NULL) == 0)
		ip->lastreset = timer->tv_sec;
	free(timer);
}

/**
 * Set requests/replies to 0 for a given IP.
 *
 */

void blanknetarps(struct ipdetails *ip){
	if (ip != NULL){
		ip->replies = 0;
		ip->requests = 0;
	}
}
