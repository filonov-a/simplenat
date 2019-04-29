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


char * header=NULL;
int post=0;

/* Function Prototypes */
static void usage(char *name);

static void print_record(void *record, char *s );

static void process_data(const char*);
static unsigned long long count;
static int showCount;
/* Functions */

#include "nffile_inline.c"

typedef struct {
    uint32_t time;
    uint32_t srcaddr;
    uint32_t nataddr;
    uint32_t dstaddr;
    uint16_t srcport;
    uint16_t natport;
    uint16_t dstport;
    uint8_t proto;
    uint8_t type;
} outdata;

char outbuff[sizeof(outdata)*1000];
int verbose=0;

static void usage(char *name) {
    printf("usage %s [options] \n"
            "-h\t\tthis text you see right here\n"
            "-r\t\tread input from file\n"
            "-M <expr>\tRead input from multiple directories.\n"
            "-R <expr>\tRead input from sequence of files.\n"
            "-o <file>\tWrite binary dump to file. \'-\' -  stdout\n"
            "-H <string>\tWrite header into beginning of outfile.\n"
            "-P <string>\tURL for HTTP POST Header.\n"
            "-v \tDump each packet to stdout.\n"
            , name);
} /* usage */

static void print_record(void *record, char *s ) {
    char 		as[40], ds[40], ns[40], datestr1[64], datestr2[64];
    time_t		when;
    struct tm 	*ts;
    master_record_t *r = (master_record_t *)record;

    r->v4.srcaddr = htonl(r->v4.srcaddr);
    r->v4.dstaddr = htonl(r->v4.dstaddr);
    r->xlate_src_ip.v4 = htonl(r->xlate_src_ip.v4);
    inet_ntop(AF_INET, &r->v4.srcaddr, as, sizeof(as));
    inet_ntop(AF_INET, &r->v4.dstaddr, ds, sizeof(ds));
    inet_ntop(AF_INET, &r->xlate_src_ip.v4, ns, sizeof(ns));

    as[40-1] = 0;
    ds[40-1] = 0;
    ns[40-1] = 0;

    when = r->first;
    ts = localtime(&when);
    strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);

    when = r->last;
    ts = localtime(&when);
    strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", ts);

    snprintf(s, 1023, "\n"
            "Flow Record: evt = %d xevt%d \n"
            "  srcaddr     = %16s\n"
            "  dstaddr     = %16s\n"
            "  nataddr     = %16s\n"
            "  first       =       %10u [%s]\n"
            "  last        =       %10u [%s]\n"
            "  proto       =              %3u\n"
            "  srcport     =            %5u\n"
            "  dstport     =            %5u\n"
            "  xsrcport    =            %5u\n"
            , 
            r->event,r->fw_xevent,as, ds, ns,r->first, datestr1, r->last, datestr2,
            r->prot, r->srcport, r->dstport,r->xlate_src_port);
    s[1024-1] = 0;

} // End of print_record

static void write_data(FILE *F,void *record) {
    char  datestr[64];
    time_t when;
    struct tm *ts;
    master_record_t *r = (master_record_t *)record;

    when = r->first;
    ts = localtime(&when);
    strftime(datestr, 63, "%Y-%m-%d", ts);
    if(post) {
        fprintf (F,"%u\t%u\t%u\t%u\t%hu\t%hu\t%hu\t%hhu\t%hhu\n",
                r->first,
                r->v4.srcaddr,
                r->xlate_src_ip.v4,
                r->v4.dstaddr,

                r->srcport,
                r->xlate_src_port,
                r->dstport,

                r->prot,
                r->event
                );
    } else {
        fprintf (F,"%s\t%u\t%u\t%u\t%hu\t%hu\t%hu\t%hhu\t%hhu\n",
                datestr,
                r->v4.srcaddr,
                r->xlate_src_ip.v4,
                r->v4.dstaddr,

                r->srcport,
                r->xlate_src_port,
                r->dstport,

                r->prot,
                r->event

                );  }
} // End of print_record
static char outbuffer[1024*1024*1024];

static void process_data(const char* outfile) {
    master_record_t	master_record;
    common_record_t *flow_record;
    nffile_t		*nffile;
    int 		i, done, ret;
    FILE *F=NULL;

    // Get the first file handle
    if(outfile !=NULL){
        if(strcmp(outfile,"-") != 0 ){
            F = fopen(outfile,"w");
            setbuffer(F,outbuffer,sizeof(outbuffer));
        } else {
            F= stdout;
        }
        if(F == NULL){
            LogError("Cannot open output file %s in %s line %d: %s\n",outfile, __FILE__, __LINE__, strerror(errno) );
            exit(EXIT_FAILURE);
        } 
        setbuffer(F,outbuff,sizeof(outbuff));
        //if(post) 
        //  fprintf(F,"POST %s HTTP/1.0\r\n\r\n",post);
        if(header) 
            fputs(header,F);
    }
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
                                               count++;
                                               if(verbose){
                                                   print_record(&master_record, string);
                                                   printf("%s\n", string);
                                               }

                                               if(F) { 
                                                   write_data(F,&master_record);
                                               }
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
    if(F){
        fclose(F);
    }
    if(showCount){
        fprintf(stderr,"Records processed: %llu\n",count);
    }
} // End of process_data


int main( int argc, char **argv ) {
    char 		*rfile, *Rfile, *Mdirs,*outfile=NULL;
    int			c;

    rfile = Rfile = Mdirs = NULL;
    while ((c = getopt(argc, argv, "PvcL:r:M:R:o:H:")) != EOF) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            case 'v':
                verbose = 1;
                break;
            case 'c':
                showCount=1;
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
            case 'H':
                header = optarg;
                break;
            case 'P':
                post = 1;
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
    process_data(outfile);

    FreeExtensionMaps(extension_map_list);

    return 0;
}
