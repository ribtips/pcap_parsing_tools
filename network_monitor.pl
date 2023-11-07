#!/usr/bin/perl

# A simple sniffer example that will print out the stack as it's happening...

use strict;
use warnings;
use FindBin;
use Data::Dumper;
use Net::Pcap;

use lib "$FindBin::Bin";
use My::pcapReader qw(interpret_global_header interpret_packet_header);
use My::StackWalk qw(stackwalk);
use My::Protocols qw(ethernet);

my $errbuf;
my $pack_num=0;

&main;

sub main {
    my $device = pcap_lookupdev(\$errbuf);
    if (defined $errbuf) {die "Unable to find device: ",$errbuf;}
    print "My device is $device!\n";

    my $handle = pcap_open_live($device, 65534, 1, 0, \$errbuf);

    pcap_loop($handle, -1, \&process_packet, "for demo");
    
    pcap_close($handle);
}

sub process_packet {
    $|=1;
    $pack_num++;
    my ($user, $header, $packet)=@_;
    my $size=length($packet);
    my ($struct,$description)=stackwalk(\$packet,0,1);
    #print Dumper $struct;
    my $tcp_present=&determine_tcp($struct);
    print "Pkt:$pack_num Sz:$size -  $description\n";
    if ($tcp_present==1) {
        print "Pkt:$pack_num Sz:$size -  $description\n";
    }
}

sub determine_tcp {
    my $struct=shift;
    foreach my $layer (keys %{$struct}) {
        if ($$struct{$layer}{'name'} eq "TCP") {
            return(1);
        }
    }
    return(0);
}




