bin_PROGRAMS = antidote
antidote_SOURCES = antidote.c audit.c alert.c checkopts.c handledata.c errors.c antidote.h errors.h includes.h

###
# Everything below this point is debug code and can be removed before release.
###

OBJFLAGS = -c
PROGFLAGS = -o
DEBUGFLAGS = -g3 -dp -Wall
LINKFLAGS = -lpcap
OBJFILES = alert.o handledata.o audit.o checkopts.o errors.c antidote.c

DEBUG_checkoptions:
	$(CC) $(DEBUGFLAGS) $(OBJFLAGS) checkopts.c

DEBUG_audit:
	$(CC) $(DEBUGFLAGS) $(OBJFLAGS) audit.c

DEBUG_alert:
	$(CC) $(DEBUGFLAGS) $(OBJFLAGS) alert.c 

DEBUG_handledata:
	$(CC) $(DEBUGFLAGS) $(OBJFLAGS) handledata.c

DEBUG_errors:
	$(CC) $(DEBUGFLAGS) $(OBJFLAGS) errors.c

DEBUG_prog:
	$(CC) $(DEBUGFLAGS) $(OBJFLAGS) antidote.c

DEBUG: DEBUG_checkoptions DEBUG_errors DEBUG_handledata DEBUG_audit DEBUG_alert
	$(CC) $(DEBUGFLAGS) $(PROGFLAGS) $(bin_PROGRAMS) $(OBJFILES) $(LINKFLAGS) 
