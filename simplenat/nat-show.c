#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>

typedef union  {
    uint32_t w;
    uint8_t  o[4];
}ipv4;

typedef struct {
  uint32_t time;
  ipv4 srcaddr;
  ipv4 nataddr;
  ipv4 dstaddr;
  uint16_t srcport;
  uint16_t natport;
  uint16_t dstport;
  uint8_t proto;
  uint8_t type;
} natdata;

FILE *F;
static void usage(char *name) {
  printf("usage %s [options] filenames \n"
	 "\t-h\tthis text you see right here\n"
	 "\t-s\tsource IP\n"
	 "\t-d\tdestination IP\n"
	 "\t-n\ttranslated IP\n"
	 "\t-S\tsource IP port\n"
	 "\t-D\tdestination IP port\n"
	 "\t-N\ttranslated IP port\n"
	 "\t-p\tIP protocol\n"
	 "\t-v \tDump each packet to stdout.\n"
	 , name);
} /* usage */
static int verbose = 0;
char outbuff[sizeof(natdata)*1000];
  ipv4 sa,da,na;
  uint16_t sp,dp,np;
  uint8_t proto;
  static int saf,daf,naf,spf,dpf,npf,protof;
void string2ip(ipv4 *ip,const char *s){
  int n;
  n = sscanf(s,"%hhu.%hhu.%hhu.%hhu",
	     &(ip->o[0]),
	     &(ip->o[1]),
	     &(ip->o[2]),
	     &(ip->o[3])
	     );
  if(n != 4){
    fprintf(stderr,"Bad ip format: %s\n",s);
    exit(EXIT_FAILURE);
  }
}
void parse_file(const char* fname){
  natdata o;
  size_t size;
  char datestr[64];
  struct tm 	*ts;
  time_t when;

   if(verbose){
     fprintf(stderr,"Parse file %s\n",fname);
   }
   F=fopen(fname,"r");
   if(F == NULL){
     fprintf(stderr, "Cannot open file '%s': %s\n",fname, strerror(errno));
     exit(EXIT_FAILURE);
   }

   setbuffer(F,outbuff,sizeof(outbuff)); //turn on bufferization
   while(!feof(F)){
     size = fread(&o,sizeof(o),1,F);
     if(size < 1 ) break;
       if(verbose){
	 printf (" %08x %08x %08x %08x %04hx %04hx %04hx %hhx %hhx\n",
		 o.time, o.srcaddr.w, o.nataddr.w, o.dstaddr.w,
		 o.srcport, o.natport, o.dstport, o.proto,o.type
		 );   
       }

     if((saf  && sa.w != o.srcaddr.w) ||
	(daf  && da.w != o.dstaddr.w) ||
	(naf  && na.w != o.nataddr.w) ||
	(spf  && sp != o.srcport) ||
	(dpf  && dp != o.dstport) ||
	(npf  && np != o.natport) ||
	(protof && proto != o.proto))
       {
	 if(verbose)
	   printf("skiprecord\n");
	 continue;
       }
     when = o.time;
     ts = localtime(&when);
     strftime(datestr, 63, "%Y-%m-%d %H:%M:%S", ts);
     printf ("%s\t"
	     "%hhu.%hhu.%hhu.%hhu\t"
	     "%hhu.%hhu.%hhu.%hhu\t"
	     "%hhu.%hhu.%hhu.%hhu\t"
	     "%5hu\t%5hu\t%5hu\t%03hu\t%hhu\n",
	     datestr, 
	     o.srcaddr.o[0],o.srcaddr.o[1],o.srcaddr.o[2],o.srcaddr.o[3],
	     o.nataddr.o[0],o.nataddr.o[1],o.nataddr.o[2],o.nataddr.o[3],
	     o.dstaddr.o[0],o.dstaddr.o[1],o.dstaddr.o[2],o.dstaddr.o[3],
	     o.srcport, o.natport, o.dstport, o.proto,o.type
	     );   

     
   }
   fclose(F);
}
int main(int argc,char ** argv){
  int c;
  int n;
  while ((c = getopt(argc, argv, "vs:d:n:S:D:N:p:")) != EOF) {
    switch (c) {
    case 's':
      string2ip(&sa, optarg);
      saf=1;
      break;
    case 'd':
      string2ip(&da, optarg);
      daf=1;
      break;
    case 'n':
      string2ip(&na, optarg);
      naf=1;
      break;
    case 'S':
      sp = atoi(optarg);
      spf=1;
      break;
    case 'D':
      dp = atoi(optarg);
      dpf=1;
      break;
    case 'N':
      np = atoi(optarg);
      npf=1;
      break;
    case 'p':
      proto = atoi(optarg);
      protof=1;
      break;
    case 'v':
      verbose = 1;
      break;
    default:
      usage(argv[0]);
      exit(EXIT_SUCCESS);
    }
 }
if (optind >= argc) {
  fprintf(stderr, "Expected filelist options\n");
  usage(argv[0]);
  exit(EXIT_FAILURE);
 }
 for(c = optind;c<argc;c++) 
   parse_file(argv[c]);
  return 0;
}
