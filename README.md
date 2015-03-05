# Simplenat tools

We need to capture and keep extremely big  data of IPv4 NAT translation information from Cisco ASR.
simplenat format can save up to 80% disk space without compression.

Format of nat-files really very simple.
Fixed size records, 24 bytes each.

uint32 unixtime
uint32 source address
uint32 translate address
uint32 destionation address
uint16 source port
uint16 translate port
uint16 destionation port
uint8 IP protocol
uint8 type of NEL event (usually 1 CREATE, 2 DELETE)


##nf2nat
Extract IPv4 NAT Info from nfcapd-captured  NEL log files to simple NAT format.
Codebase of nfdump 1.6.9 or greater with NEL support required to build this one - see Makefile

usage nf2nat [options] 
-h              this text you see right here
-r              read input from file
-M <expr>       Read input from multiple directories.
-R <expr>       Read input from sequence of files.
-o <file>       Write binary dump to file.
-v      Dump each packet to stdout.

Example:
    nf2nat -r nfcapd.xxx -o nat.xxx


##nat-show

Parser nat files.
Can filter output by any field combination.

usage nat-show [options] filenames 
        -h      this text you see right here
        -s      source IP
        -d      destination IP
        -n      translated IP
        -S      source IP port
        -D      destination IP port
        -N      translated IP port
        -p      IP protocol
        -v      Dump each packet to stdout.

Example:
nat-show -s 10.100.77.199 -D 80 ../nat.file

##show.pl

Very simple parser on perl

