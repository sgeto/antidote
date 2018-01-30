/* -*- project-c -*- */
/**
 * \file errors.h
 * \brief Header definitions of errors.
 */

/**
 * The following are errors which any function may return. Their meanings
 * are:
 *
 * \c OK - Function executed successfully.
 * \c ERR_LOOKUPDEV - Cannot find an ethernet device
 * \c ERR_OPENLIVE - Cannot open the ethernet device
 * \c ERR_COMPILEBPF - Cannot compile the BPF program 
 * \c ERR_SETFILTER - Cannot set the filter on the ethernet device
 * \c ERR_NOMEM - Cannot allocate memory
 * \c ERR_BADUSAGE - Function incorrectly used. Should never happen, but...
 * \c ERR_MACCHANGED - MAC address has changed
 * \c ERR_NOOPTSFILE - Cannot find options file
 * \c ERR_INOPTS - Error parsing options file
 * \c ERR_CANNOTGETMAILSERVER - Cannot find mail server
 * \c ERR_CONNECTMAILSERVER - Cannot connect to mail server.
 *
 * *Most* functions will only return OK and ERR_NOMEM.
 */
#define OK 0
#define ERR_LOOKUPDEV 1
#define ERR_OPENLIVE 2
#define ERR_COMPILEBPF 3
#define ERR_SETFILTER 4
#define ERR_NOMEM 5
#define ERR_BADUSAGE 6
#define ERR_MACCHANGED 7
#define ERR_NOOPTSFILE 8
#define ERR_INOPTS 9
#define ERR_CANNOTGETMAILSERVER 10
#define ERR_CONNECTMAILSERVER 11
#define ERR_LOOKUPNET 12
#define ERR_CONNECTCLOSED 13
#define ERR_WRONGREPLY 14
#define ERR_EOF 15
