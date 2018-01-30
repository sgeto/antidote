/* -*- project-c -*- */

/**
 * \file antidote.c
 * \brief A program to detect the presence of possible ARP poisoners.
 * \author James Cort, (C) 2001.  Email antidote@whitepost.org.uk
 *
 * A program to detect the presence of, and alert the operator to, the presence of
 * packet sniffers making use of ARP poisoning.
 *
 * Some of the packet capture and filtering code is inspired by 
 * testpcap3.c by Martin Casado.
 *
 * All other code was written by James Cort, edited in GNU Emacs, compiled using gcc
 * and tested on Mandrake and Slakware Linux, and FreeBSD 4.2. For full information,
 * including acknowledgements, program design and documentation, please see the
 * write up.
 *
 */

#include "antidote.h"
#define POISONER 1


/**
 * Do the donkey work for handling an ARP request. This consists of:
 * - Checking for the presence of the given IP address in the data structure
 * - Creating a new holder for the details if none exists
 * - Adding to the number of requests received.
 *
 * ARGUMENTS:
 * \arg \c **info - On finishing, this will be a pointer to the area of memory 
 * containing the IP details for the IP address checked.
 *
 * \arg \c *frame - A pointer to a raw Ethernet frame to process.
 *
 * RETURN VALUES:
 * \return OK
 * \return ERR_NOMEM
 *
 */
		
int handlerequest(struct ipdetails **info, const char *frame) {
	u_int8_t *ipaddress;
	struct ipdetails *temp;
	struct ether_arp *arpbody;
	arpbody = (struct ether_arp *) (frame + sizeof(struct ether_header));  /* we'll need ether_arp->arp_sha later */
	ipaddress = arpbody->arp_tpa;
	/* ipaddress = getipaddress(frame);*/
	temp = checkip(*info, ipaddress);
	if (temp == NULL) { // the IP given does not exist in the data
		temp = createipspace();	 // create space for it
		if (temp == NULL) 
			return ERR_NOMEM;				
		populateipspacereq(temp, frame);      	
		temp->previous = *info; //link into the data
		temp->next = (*info)->next;
		(*info)->next = temp;		
	}
	*info = temp;
	addrequest(temp);
	return OK;
}

/**
 * Do the donkey work for handling an ARP reply.
 *
 * If details for the machine expressed in the ARP reply aren't currently in 
 * memory, add them.
 *
 * See also handlerequest()
 *
 * ARGUMENTS:
 * \arg \c **info - On finishing, this will be a pointer to the area of memory 
 * containing the IP details for the IP address checked.
 *
 * \arg \c *frame - A pointer to a raw Ethernet frame to process.
 *
 * RETURN VALUES:
 * \return OK
 * \return ERR_NOMEM
 */	

int handlereply(struct ipdetails **info, const char *frame) {
	u_int8_t *ipaddress;
	int loop;
	struct ipdetails *temp;	
	struct ether_arp *arpbody;
	struct ether_header *etherhead;
  	arpbody = (struct ether_arp *) (frame + sizeof(struct ether_header));  /* we'll need ether_arp->arp_sha later */
	ipaddress = arpbody->arp_spa; /* we want the sender for a reply, the recipient  for a request*/
	temp = checkip(*info, ipaddress);
	if (temp == NULL) { // the IP given does not exist in the data
		temp = createipspace();	 // create space for it
		if (temp == NULL) 
			return ERR_NOMEM;				
		populateipspacerep(temp, frame);	      	
		temp->previous = *info; //link into the data
		temp->next = (*info)->next;
		(*info)->next = temp;
	} else if (sumbytes((u_int8_t *)(temp->mac_address), ETH_ALEN) == 0){
		/*
		 * If the MAC address as held is 0, we've never seen a reply from this machine.
		 */
		etherhead = (struct ether_header *) frame;
		for(loop = 0; loop < ETH_ALEN; loop++){
			temp->mac_address[loop] = etherhead->ether_shost[loop];
		}      
	}
	*info = temp;
	addreply(temp);
	return OK;
}

/**
 * Process a raw Ethernet packet. This routine will:
 * - Check the sender MAC in Ethernet frame and ARP packet tally.
 * - Put the ARP packet contained within the Ethernet frame into a 
 *   data structure holding ARP details
 * - Process the ARP packet for IP details.
 * 
 * ARGUMENTS:
 * \arg \c *frame - A pointer to a raw Ethernet frame.
 *
 * RETURN VALUES:
 * \return ERR_OK
 * \return ERR_NOMEM
 */	
int processether(const u_char *frame){
	int tempint;
	u_int16_t *temp;
	struct ether_arp *arpbody;
	struct arphdr *arpheader;
	static struct ipdetails *entrypoint = NULL;
	temp = malloc(sizeof(u_int16_t));
	if (temp == NULL) {
		redalert("Cannot allocate memory to store temporary variables");
		return ERR_NOMEM;
	}
/* Start our data structure */

	if (entrypoint == NULL) // the data structure is empty.
	       entrypoint = createipspace();
	if (entrypoint == NULL) {
		redalert("Cannot allocate memory to store IP details");
		free(temp);
		return ERR_NOMEM;
	}
        if (entrypoint->ip_address[0] == 0) { // only used 1st time routine called.
		populateipspace(entrypoint, frame);
	}

	frame += sizeof(struct ether_header);
	arpheader = (struct arphdr *) frame;
  	arpbody = (struct ether_arp *) frame;  /* we'll need ether_arp->arp_sha later */
	frame -= sizeof(struct ether_header);  /* we also need frame to point to where it started */
	*temp = (u_int16_t)arpheader->ar_op;
	*temp = ntohs(*temp);

	if (*temp == ARPOP_REQUEST){
		tempint = handlerequest(&entrypoint, frame);
		if (tempint == ERR_NOMEM)
			redalert("Out of Memory for IP details");
		else{		
			/*
			 * Strikes me that there's not much point checking for IP->MAC changes
			 * when examining ARP *requests*.
			 */
			//if (checkmacchanges(entrypoint, arpbody->arp_sha) != OK)
			// populateipspacereq(entrypoint, frame); // totally unnecessary - handlerequest() (above) does that & we're not checking for changes.
			processip(&entrypoint);
		}
	}
	else if (*temp == ARPOP_REPLY){
		tempint = handlereply(&entrypoint, frame);
		if (tempint == ERR_NOMEM)
			redalert("Out of Memory for IP details");
	        else {
			if (checkmacchanges(entrypoint, arpbody->arp_sha) != OK)
				populateipspacerep(entrypoint, frame);
			processip(&entrypoint);
		}
	}
	else notice("Unrecognised ARP type detected (RARP not currently supported)");
/* Remove this after debugging */
	dumpdata(entrypoint,"DETAILS.csv");
	return OK;
}

/**
 * Process a given set of details referring to an IP.
 * Processing tdfo include:
 * - Checking for unusual, unbalanced numbers of ARPs
 * - Checking timeframe on the details to ensure we're not looking at ancient info.
 *
 * Sets info to a pointer to the resulting IP details - useful if the details are old
 * enough to be removed. 
 *
 * ARGUMENTS:
 * \arg \c **info - A pointer to an ipdetails struct to process.
 *
 * \todo Tidy up removing IP details from the data structure - if the network
 * this is on uses fixed IP addressing it might be desirable to never remove
 * details, and if it uses DHCP, there's no point in keeping details too long.
 * That being said, how the blazes is anyone supposed to spot an odd
 * machine on the network if the network is using DHCP?!
 */

void processip(struct ipdetails **info){

	struct ipdetails *temp1 = NULL, *temp2;
	char *msg;
/*
 * First, out with the old. We're not too bothered about unusual
 * numbers of ARP requests if thery're only sent once every couple of hours - it's
 * unlikely to be a serious poisoning attempt.
 */
	temp2 = *info;
	temp1 = checktimeouts(*info);
	if (temp1 != temp2) {
		// info has been removed, no further checking.
		*info = temp1;
		return;
	}

/* 
 * Unbalanced ARP numbers : Update to give MAC details of poisoner.
 */

	if (checknetarps(*info) > POISON_THRESHOLD){
		msg = malloc(ADOTE_ERR_BUFF); // D'oh!
		if (msg != NULL) {
			sprintf(msg,"Suspected poisoner impersonating IP address: %d.%d.%d.%d", (*info)->ip_address[0], (*info)->ip_address[1], (*info)->ip_address[2], (*info)->ip_address[3]);
			redalert(msg);
			free(msg);
		} else {
			redalert("Suspected poisoner detected. Unable to allocate memory for details.");
		} 
	} else if (checknetarps(*info) < options.badnet_threshold){
		msg = malloc(ADOTE_ERR_BUFF); 
		if (msg != NULL) {
			sprintf(msg,"An unusual number of ARP requests for: %d.%d.%d.%d have not been replied to", (*info)->ip_address[0], (*info)->ip_address[1], (*info)->ip_address[2], (*info)->ip_address[3]);
			redalert(msg);
			free(msg);
		} else {
			redalert("An unusual number of ARP requests have not been replied to. Unable to allocate memory for details.");
		} 
	}
	if ((checknetarps(*info) > options.poison_threshold) || (checknetarps(*info)< options.badnet_threshold)){
		blanknetarps(*info);
		resettimer(*info);
	}
	//removeip(*info); // on second thoughts, that's stupid.
}
	
/**
 * This routine will be called repeatedly, every time an ARP is detected.
 * 
 * It is nothing more than a wrapper around processether, which does most of the hard
 * work.
 *
 * I'm wrapping it purely so that all the routines I use receive only what they need, and to stop me
 * having to worry about other baggage introduced by callback.
 *
 * ARGUMENTS:
 * \arg \c *useless - An unsigned char which the documentation for libpcap insists must be
 * present. I don't know why.
 * \arg \c *pkthdr - The Ethernet frame header.
 * \arg \c *frame - The Ethernet frame itself (includes header).
 *
 */
void my_callback(u_char *useless,const struct pcap_pkthdr* framehdr,const u_char* frame)
{
	processether(frame);
	/**
	 * I suspect libpcap uses the same piece of memory for each frame it passes
	 * to callback, so I'm not going to free that memory pointer.
	 */
}

/**
 * Initialise our tester (I hesitate to say sniffer, it may not be sniffing...)
 *
 * Will initialise *devopen, or the first non-loopback interface if *devopen
 * is not defined.
 *
 * ARGUMENTS:
 * \arg \c *devopen - A pointer to a null-terminated string describing the device 
 * to open. If NULL, will open the first device it finds.
 *
 * RETURNS:
 * \return ERR_LOOKUPDEV 
 * \return ERR_OPENLIVE  
 * \return ERR_COMPILEBPF
 * \return ERR_SETFILTER 
 *
 * In use, this routine shouldn't actually return anything, because the last call is one to
 * pcap_loop, which loops eternally, but hey... shit happens.
 */
int initether(char *devopen){
	char *dev; 
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	struct bpf_program fp;      /* hold compiled program     */
	bpf_u_int32 maskp;          /* subnet mask               */
	bpf_u_int32 netp;           /* ip                        */
	
	if (strcmp(devopen, DEFAULTDEVICE) == 0) {
		dev = pcap_lookupdev(errbuf);
	}else{
		dev = devopen;
	}
	if (dev == NULL) {
		return ERR_LOOKUPDEV;
	}
	if (pcap_lookupnet(dev,&netp,&maskp,errbuf) == -1){
		return ERR_LOOKUPNET;
	}
/*
 * pcap 0.5 doesn't like a -1 read timeout
 */
	descr = pcap_open_live(dev,BUFSIZ,options.promiscuous,10,errbuf);
	if (descr == NULL){
		return ERR_OPENLIVE;
	}
	if(pcap_compile(descr,&fp,options.bpf_program,0,netp) == -1){
		return ERR_COMPILEBPF;
	}
	if(pcap_setfilter(descr,&fp) == -1) {
		return ERR_SETFILTER;
	}
	pcap_loop(descr,-1,my_callback,NULL);
	return OK;
}

void showusage(int argc, char **argv){
	printf("Usage: %s [-f config-file|-h]\n\n", argv[0]);
	printf("-f : Select a different configuration file. The default is %s.\n", OPTSFILE);
	printf("-h : Print this help\n");
}


int main(int argc,char **argv)
{ 
	int init = OK;
	char error[ADOTE_ERR_BUFF];
	if (setdefaults() != OK) {
		fprintf(stdout, "Unable to allocate memory to set options. Quitting.\n");
		exit(ERR_NOMEM);
	}
	if ((init = processarguments(argc, argv)) != OK)
		exit(init);
	loadoptions();
	init = initether(options.device); /* should NEVER return */
	if (init != OK){
		decodeerror(init, error);
		bluealert(error);
	    /*  
		Paranoid? Perhaps, but this could be initialised on bootup, 
		in which case there may be nobody to witness a failure to
		init.
	    */ 
	}
    return init;
    // it's easy, m'kay...
}
