#!/usr/bin/perl -w
use strict;

foreach my $fname (@ARGV){
    open(F,$fname) or die "cannot opent file $!";
    #binmode(F,":raw");
    while(!eof(F)){
	my $v;
	my $res=read F,$v,24;
	last if $res<24;
	my @r=unpack "LCCCCCCCCCCCCSSSCC",$v;
	$r[0]=strftime ("%F %T", localtime($r[0])),
	printf  "%s\t%d.%d.%d.%d\t%d.%d.%d.%d\t%d.%d.%d.%d\t%d\t%d\t%d\t%d\t%d\n",@r;
    }
    close(F);
}
