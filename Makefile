LINK_TARGET = dns_hijack

OBJS = \
	dns_hijack.o header.o dns.o
	
REBUILDABLES = $(OBJS) $(LINK_TARGET)

all : $(LINK_TARGET)

clean: 
	rm -f $(REBUILDABLES)

dns_hijack : dns_hijack.o header.o dns.o
	gcc -g  -o  $@ $^ -lpcap
	

%.o : %.c
	gcc -g   -Wall -o $@ -c $< 
