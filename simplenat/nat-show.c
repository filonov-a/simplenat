#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>

#include <archive.h>
#include <archive_entry.h>

typedef union  {
  uint32_t w;
  uint8_t  o[4];
}ipv4;

#define MAX_FIELD 32
#define PUSH_IP(a)   if( (a##Count) < MAX_FIELD){  string2ip(&(a[(a##Count)++]), optarg);}
#define PUSH_PORT(a)   if( (a##Count) < MAX_FIELD){ a[(a##Count)++]=atoi(optarg);}

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
      "\t-e\tNEL event type: 1 CREATE, 2 DELETE\n"
      "\t-v \tDump each packet to stdout.\n"
      , name);
} /* usage */
static int verbose = 0;
char outbuff[sizeof(natdata)*1000];
ipv4 sa[MAX_FIELD],da[MAX_FIELD],na[MAX_FIELD];
uint16_t sp[MAX_FIELD],dp[MAX_FIELD],np[MAX_FIELD];
uint8_t proto,evt;

static int protof,evtf;
static int saCount,daCount,naCount,spCount,dpCount,npCount;

int findIp(int count,ipv4 *ip,ipv4 v){
  int i;
  for(i=0; i<count;i++){
    if(v.w == ip[i].w) {
      if(verbose)
        printf("IP Filter[%d] matched : %hhu.%hhu.%hhu.%hhu\n",i,
            ip[i].o[3],ip[i].o[2],ip[i].o[1],ip[i].o[0]);

      return 1;
    }
  }
  return 0;
}

int findPort(int count,uint16_t *port,uint16_t v){
  int i;
  for(i=0; i<count;i++){
    if(v == port[i]) return 1;
  }
  return 0;
}
void string2ip(ipv4 *ip,const char *s){
  int n;
  n = sscanf(s,"%hhu.%hhu.%hhu.%hhu",
      &(ip->o[3]),
      &(ip->o[2]),
      &(ip->o[1]),
      &(ip->o[0])
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
  struct archive *a;
  struct archive_entry *entry;
  int r;
  int found;

  if(verbose){
    fprintf(stderr,"Parse file %s\n",fname);
  }
  a = archive_read_new();
  archive_read_support_filter_all(a);
  archive_read_support_format_raw(a);

  r = archive_read_open_filename(a, fname,4096000); // Note 1
  if (r != ARCHIVE_OK) {
    fprintf(stderr,"error %d :%s\n",archive_errno(a),archive_error_string(a));
    exit(1);
  }
  while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
    if(verbose){
      printf("Read next entry \"%s\"\n",archive_entry_pathname(entry));
    }
    while((size = archive_read_data(a, &o, sizeof(o))) > 0){
      //printf("Readed %lu bytes\n",size);
      /*      if(verbose){
              printf (" %08x %08x %08x %08x %04hx %04hx %04hx %hhx %hhx\n",
              o.time, o.srcaddr.w, o.nataddr.w, o.dstaddr.w,
              o.srcport, o.natport, o.dstport, o.proto,o.type
              );
              }
       */
      found = 0;
      if(findIp(saCount, sa, o.srcaddr)  ||
          findIp(daCount, da ,o.dstaddr) ||
          findIp(naCount, na ,o.nataddr) ||
          findPort(spCount, sp, o.srcport) ||
          findPort(dpCount, dp, o.dstport) ||
          findPort(npCount, np, o.natport) ||
          (evtf && evt == o.type)   ||
          (protof && proto == o.proto))
      {
        found = 1;
      }
      if(!found){
        if(verbose) {
          printf("SKIP: ");
        } else {
          continue;
        }
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
          o.srcaddr.o[3],o.srcaddr.o[2],o.srcaddr.o[1],o.srcaddr.o[0],
          o.nataddr.o[3],o.nataddr.o[2],o.nataddr.o[1],o.nataddr.o[0],
          o.dstaddr.o[3],o.dstaddr.o[2],o.dstaddr.o[1],o.dstaddr.o[0],
          o.srcport, o.natport, o.dstport, o.proto,o.type
          );   
    }
    archive_read_data_skip(a);  // Note 2
  }

  r = archive_read_free(a);  // Note 3
  if (r != ARCHIVE_OK){
    printf("error %d :%s\n",archive_errno(a),archive_error_string(a));
    exit(1);
  }
}
int main(int argc,char ** argv){
  int c;
  int n;
  while ((c = getopt(argc, argv, "vs:d:n:S:D:N:p:e:")) != EOF) {
    switch (c) {
      case 's':
        PUSH_IP(sa);
        break;
      case 'd':
        PUSH_IP(da);
        break;
      case 'n':
        PUSH_IP(na);
        break;
      case 'S':
        PUSH_PORT(sp);
        break;
      case 'D':
        PUSH_PORT(dp);
        break;
      case 'N':
        PUSH_PORT(np);
        break;
      case 'p':
        proto = atoi(optarg);
        protof=1;
        break;
      case 'e':
        evt = atoi(optarg);
        evtf=1;
        break;
      case 'v':
        verbose = 1;
        break;
      default:
        usage(argv[0]);
        exit(EXIT_SUCCESS);
    }
  }
  if(verbose){
    for(int i=0;i<saCount;i++){
      printf("SA Filter[%d] : %hhu.%hhu.%hhu.%hhu\n",i,
          sa[i].o[3],sa[i].o[2],sa[i].o[1],sa[i].o[0]);
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
