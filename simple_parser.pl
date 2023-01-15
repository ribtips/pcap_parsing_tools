#!/usr/bin/perl

use strict;
use warnings;
use FindBin;
use Data::Dumper;

use lib "$FindBin::Bin";
use My::pcapReader qw(interpret_global_header interpret_packet_header);
use My::StackWalk qw(stackwalk);
use My::Protocols qw(ethernet);

&main;

sub main {
    open(my $fh,$ARGV[0]);
    binmode($fh);
    read($fh,my $global_header,24);
    my $gh=interpret_global_header(\$global_header);
    until(eof($fh)) {
        read($fh, my $packet_header,16);
        my $ph=interpret_packet_header(\$packet_header);
        read($fh,my $payload,$$ph{'incl_len'});
        my ($struct,$description)=stackwalk(\$payload,0,$$gh{'dlt'});
        print "PacketStack: $description\n";
    }
    close($fh);
}
