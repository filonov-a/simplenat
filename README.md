# Simplenat tools

We need to capture and keep extremely big  data of IPv4 NAT translation information from Cisco ASR.
simplenat format can save up to 80% disk space without compression.
```
%time simplenat/nf2nat -r nfcapd.13g -o nat.13g 
simplenat/nf2nat -r nfcapd.13g -o nat.13g  25,59s user 15,48s system 17% cpu 3:48,92 total
% du -sh *.13g
2,6G    nat.13g
 13G    nfcapd.13g
```

Format of nat-files really very simple.
Fixed size records, 24 bytes each.
```
uint32 unixtime
uint32 source address
uint32 translate address
uint32 destionation address
uint16 source port
uint16 translate port
uint16 destionation port
uint8 IP protocol
uint8 type of NEL event (usually 1 CREATE, 2 DELETE)
````

##nf2nat
Extract IPv4 NAT Info from nfcapd-captured  NEL log files to simple NAT format.
Codebase of nfdump 1.6.9 or greater with NEL support required to build this one - see Makefile

usage nf2nat [options] 
```
-h              this text you see right here
-r              read input from file
-M <expr>       Read input from multiple directories.
-R <expr>       Read input from sequence of files.
-o <file>       Write binary dump to file.
-v      Dump each packet to stdout.
````
Example:
    nf2nat -r nfcapd.xxx -o nat.xxx


##nat-show

Parser nat files.
Can filter output by any field combination.
Transparent work with compressed files supported through libarchive

```
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
```
Example:
nat-show -s 10.100.77.199  -s 10.100.77.193  -s 10.100.77.191 -D 80 ../nat.file

##show.pl

Very simple parser on perl

