/*
 *  Copyright (c) 2015, Andrew Filonov
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2009, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   * Neither the name of the author nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 *  $Author: haag $
 *
 *  $Id: nfreader.c 48 2010-01-02 08:06:27Z haag $
 *
 *  $LastChangedRevision: 48 $
 *
 *
 */

/*
 *
 * nfreader is sample code for reading nfdump binary files.
 * patched for writing simple nel dump files
 * It accepts the standard nfdump file select options -r, -M and -R
 * Therefore it allows you to loop over multiple files and process the netflow record.
 *
 * Insert your code in the process_data function after the call to ExpandRecord
 * To build the binary: first compile nfdump as usual.
 * Then compile nfreader:
 *
 * make nfreader
 *
 * This compiles this code and links the required nfdump files
 * If you do it by hand:
 *
 * gcc -c nfreader.c
 * gcc -o nfreader nfreader.o nffile.o flist.o util.o
 *
 */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "nfx.h"
#include "bookkeeper.h"
#include "nfxstat.h"
#include "collector.h"
#include "exporter.h"
#include "util.h"
#include "flist.h"

#if ( SIZEOF_VOID_P == 8 )
typedef uint64_t    pointer_addr_t;
#else
typedef uint32_t    pointer_addr_t;
#endif

// module limited globals
extension_map_list_t *extension_map_list;

extern generic_exporter_t **exporter_list;

typedef union  {
  uint32_t w;
    uint8_t  o[4];
}ipv4;


/* Function Prototypes */
static void usage(char *name);

static void print_record(void *record);

static void process_data();

/* Functions */

#include "nffile_inline.c"


int verbose=0;
static uint64_t** activity[256];

static void usage(char *name) {
  printf("usage %s [options] \n"
	 "-h\t\tthis text you see right here\n"
	 "-r\t\tread input from file\n"
	 "-M <expr>\tRead input from multiple directories.\n"
	 "-R <expr>\tRead input from sequence of files.\n"
	 "-o <file>\tWrite activity info file (default stdout).\n"
	 "-v \tverbose output.\n"
	 , name);
} /* usage */
static unsigned memstat2,memstat3;
static void print_record(void *record) {
  char 		as[40];
  master_record_t *r = (master_record_t *)record;
  ipv4 addr;
  uint64_t** ptr;
  uint64_t* bitmask;
  uint64_t maskbit;
  unsigned maskaddr;
  
  addr.w = htonl(r->v4.srcaddr);
  //r->v4.srcaddr = htonl(r->v4.srcaddr);
  //  # = htonl(r->v4.srcaddr);
  //inet_ntop(AF_INET, &addr.w, as, sizeof(as));
  //as[40-1] = 0;

  if(!activity[addr.o[0]]){
    activity[addr.o[0]] = (uint64_t**)calloc(256,sizeof(uint64_t*));
    memstat2++;
  }
  ptr =(uint64_t**) activity[addr.o[0]];
  if(!ptr[addr.o[1]]){
    ptr[addr.o[1]] = (uint64_t*)calloc(4*256,sizeof(uint64_t));
    memstat3++;
  }
  bitmask = (uint64_t*)ptr[addr.o[1]];
  maskbit = (uint64_t)1<< ( 0x3f &  addr.o[3]);
  maskaddr =  ((unsigned)addr.o[3] >> 6) | ((unsigned)addr.o[2]<<2);
  if(verbose && !(bitmask[maskaddr] & maskbit)){
    printf ( "in = %hhu.%hhu.%hhu.%hhu    \tmaskarray=%p bit=%lx addr=%u.%u \n" ,
	   addr.o[0],addr.o[1],addr.o[2],addr.o[3]
	     ,bitmask,maskbit,maskaddr, ( 0x3f &  addr.o[3])
	  );
  }
  bitmask[maskaddr] |= maskbit;

} // End of print_record

void showActivity(const char * outfile){
  unsigned i,j,k,m;
  uint64_t ** iptr,**jptr;
  uint64_t * ptr;
  uint64_t mask;
  FILE *F=stdout;
  unsigned count=0;
  // Get the first file handle
  if(outfile){
    F = fopen(outfile,"w");
    if(F == NULL){
      LogError("Cannot open output file %s in %s line %d: %s\n",outfile, __FILE__, __LINE__, strerror(errno) );
      exit(EXIT_FAILURE);
    }
  }
  
  for(i=0;i<256;i++){
    if( ! activity[i] ) continue;
    for(j=0,jptr=activity[i];j<256;j++){
      if( ! jptr[j]) continue;
      for(k=0,ptr=(uint64_t*)jptr[j];k<4*256;k++){
	  for(m=0,mask=1;m<64;m++,mask<<=1){
	    if(mask & ptr[k]){
	      fprintf( F,"%d.%d.%d.%d\n",i,j,(k>>2),(k&3)*64+m);
	      if(verbose){
		printf ( "out= %d.%d.%d.%d    \tmaskarray=%p bit=%lx addr=%u.%u \n" 
			 ,i,j,(k>>2),(k&3)*64+m
			 ,ptr,mask,k,m);
	      }
	      count++;
	    }}}}
  }
  if(outfile){
    fclose(F);
  }
  fprintf (stderr,"Total: %u addrs (%u l2 allocation, %u l3 allocation\n",count,memstat2,memstat3);
}
static void process_data() {
  master_record_t	master_record;
  common_record_t *flow_record;
  nffile_t		*nffile;
  int 		i, done, ret;
  char 		as[40];
  // Get the first file handle
  nffile = GetNextFile(NULL, 0, 0);
  if ( !nffile ) {
    LogError("GetNextFile() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
      exit(EXIT_FAILURE);
  }
  if ( nffile == EMPTY_LIST ) {
    LogError("Empty file list. No files to process\n");
      exit(EXIT_FAILURE);
  }

  done = 0;
  while ( !done ) {
    // get next data block from file
    ret = ReadBlock(nffile);

    switch (ret) {
    case NF_CORRUPT:
    case NF_ERROR:
      if ( ret == NF_CORRUPT )
	fprintf(stderr, "Skip corrupt data file '%s'\n",GetCurrentFilename());
      else
	fprintf(stderr, "Read error in file '%s': %s\n",GetCurrentFilename(), strerror(errno) );
      // fall through - get next file in chain
    case NF_EOF: {
      nffile_t *next = GetNextFile(nffile, 0, 0);
      if ( next == EMPTY_LIST ) {
	done = 1;
      }
      if ( next == NULL ) {
	done = 1;
	LogError("Unexpected end of file list\n");
      }
      // else continue with next file
      continue;

    } break; // not really needed
    }


    if ( nffile->block_header->id == Large_BLOCK_Type ) {
      // skip
      continue;
    }

    if ( nffile->block_header->id != DATA_BLOCK_TYPE_2 ) {
      fprintf(stderr, "Can't process block type %u. Skip block.\n", nffile->block_header->id);
      continue;
    }

    flow_record = nffile->buff_ptr;
    for ( i=0; i < nffile->block_header->NumRecords; i++ ) {
      char        string[1024];

      switch ( flow_record->type ) {
      case CommonRecordType: {
	uint32_t map_id = flow_record->ext_map;
	generic_exporter_t *exp_info = exporter_list[flow_record->exporter_sysid];
	if ( extension_map_list->slot[map_id] == NULL ) {
	  snprintf(string, 1024, "Corrupt data file! No such extension map id: %u. Skip record", flow_record->ext_map );
	  string[1023] = '\0';
	} else {
	  ExpandRecord_v2( flow_record, extension_map_list->slot[flow_record->ext_map],
			   exp_info ? &(exp_info->info) : NULL, &master_record);

	  // update number of flows matching a given map
	  extension_map_list->slot[map_id]->ref_count++;

	  /*
	   * insert hier your calls to your processing routine
	   * master_record now contains the next flow record as specified in nffile.c
	   * for example you can print each record:
	   *
	   */
	  print_record(&master_record);

	}

      } break;
      case ExtensionMapType: {
	extension_map_t *map = (extension_map_t *)flow_record;

	if ( Insert_Extension_Map(extension_map_list, map) ) {
	  // flush new map
	} // else map already known and flushed

      } break;
      case ExporterInfoRecordType:
      case ExporterStatRecordType:
      case SamplerInfoRecordype:
	// Silently skip exporter records
	break;
      default: {
	fprintf(stderr, "Skip unknown record type %i\n", flow_record->type);
      }
      }

      // Advance pointer by number of bytes for netflow record
      flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);

    } // for all records

  } // while

  CloseFile(nffile);
  DisposeFile(nffile);

  PackExtensionMapList(extension_map_list);
} // End of process_data


int main( int argc, char **argv ) {
  char 		*rfile, *Rfile, *Mdirs,*outfile=NULL;
  int			c;

  rfile = Rfile = Mdirs = NULL;
  while ((c = getopt(argc, argv, "vL:r:M:R:o:")) != EOF) {
    switch (c) {
    case 'h':
      usage(argv[0]);
      exit(0);
      break;
    case 'v':
      verbose = 1;
      break;
    case 'L':
      if ( !InitLog("argv[0]", optarg) )
	exit(255);
      break;
    case 'r':
      rfile = optarg;
      if ( strcmp(rfile, "-") == 0 )
	rfile = NULL;
      break;
    case 'o':
      outfile = optarg;
      break;
    case 'M':
      Mdirs = optarg;
      break;
    case 'R':
      Rfile = optarg;
      break;
    default:
      usage(argv[0]);
      exit(0);
    }
  }

  if ( rfile && Rfile ) {
    fprintf(stderr, "-r and -R are mutually exclusive. Please specify either -r or -R\n");
    exit(255);
  }
  if ( Mdirs && !(rfile || Rfile) ) {
    fprintf(stderr, "-M needs either -r or -R to specify the file or file list. Add '-R .' for all files in the directories.\n");
    exit(255);
  }

  extension_map_list = InitExtensionMaps(NEEDS_EXTENSION_LIST);
  if ( !InitExporterList() ) {
    exit(255);
  }

  SetupInputFileSequence(Mdirs, rfile, Rfile);
  process_data();

  FreeExtensionMaps(extension_map_list);
  showActivity(outfile);
  return 0;
}
