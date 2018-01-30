/* -*- project-c -*- */
/**
 * \file audit.c
 * \brief Holds code for auditing details
 * Part of Antidote, the Network Security: Packet Sniffer Detector Tool 
 * project.
 *
 * This module holds the code which "audits" details - checks they're valid
 * and sounds the alarms if they're not.
 */

#include "antidote.h"

/**
 * Calculate and return the sum of COUNT bytes, starting at *start.
 */
int sumbytes(u_int8_t *start, int count){
	int loop, result = 0;
	for (loop = 0; loop < count; loop++) {
		result += *(start+(loop * sizeof(u_int8_t)));
	}
	return result;
}

/**
 * Check a given MAC tallies with the MAC held in our
 * details, alert the operator if they don't.
 *
 * Usually used to ensure that there is no discrepancy between
 * the MAC in the Ethernet frame and the MAC in the ARP header.
 *	 
 */
void checkmacs(struct ipdetails *ipdetails, u_int8_t *ether_mac) {
	int lp, flag = 0;
	for (lp = 0; lp < ETH_ALEN; lp++) {
		if (ipdetails->mac_address[lp] != ether_mac[lp])
			flag = 1;
	}
	if (flag > 0)
		alertdodgymacs(ipdetails, ether_mac);
	return;
}

/**
 * Check a given MAC tallies with the MAC held in our
 * details, alert.
 * 
 * This function is virtually identical to checkmacs except if MACs 
 * don't tally, it calls a slightly different alerting routine which goes 
 * on to give a different message.
 *
 * Other changes include returning a value if things have changed. This
 * allows a calling function to update MAC details in the ipdetails struct if
 * necessary.
 */
int checkmacchanges(struct ipdetails *ipdetails, u_int8_t *ether_mac) {
	int lp, flag = 0;
	// don't alert if this is the first time we've seen a reply from this machine.
	if (options.check_mac_changes && (sumbytes((u_int8_t *)(ipdetails->mac_address), ETH_ALEN) != 0)){
		for (lp = 0; lp < ETH_ALEN; lp++) {
			if (ipdetails->mac_address[lp] != ether_mac[lp])
				flag = 1;
		}
		if (flag > 0){
			alertchangedmacs(ipdetails, ether_mac);
			return ERR_MACCHANGED;
		}
	}
	return OK;
}

/**
 * Checks the net number of ARP replies made for a specified IP address.
 * Returns the net number of arp replies, or NULL if no data held.
 *
 * By "net number of arp replies", we mean "arp replies minus arp requests".
 *
 * ie. a negative number implies an unusual number of unanswered requests, and 
 * a positive number implies an unusual number of unsolicited replies.
 */

int checknetarps(struct ipdetails *ip) {
	int result; 
	result = (ip->replies) - (ip->requests); 
	return result;
}

/**
 * Checks the timeout value of a given IP.
 * If the record has timed out, remove it an update the pointers of records 
 * each side.
 *
 * Returns a pointer to the next item in the list if the item is removed.
 */

struct ipdetails *checktimeouts(struct ipdetails *ip) {
	struct timeval *timer;
	struct ipdetails *before, *after;
	after = NULL;
	timer = malloc(sizeof(struct timeval));
	if (timer != NULL) {
		if (gettimeofday(timer, NULL) == 0) 
		{
			if ((ip->lastreset + options.timeout) < (timer->tv_sec)) 
			{
				before = ip->previous;
				after = ip->next;
				if (before)
					before->next = ip->next;
				if (after)
					after->previous = ip->previous;
				free(ip);
			} else
				after = ip;
		}
		free(timer);
	} else
		after = ip;
	return after;
}

