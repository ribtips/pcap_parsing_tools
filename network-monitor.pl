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
my %status=();
my %cap_stats=();
my $clear=`clear`;
my $handle;
my $timeout=60;
$|=1;

&main;

sub main {
    my $device = pcap_lookupdev(\$errbuf);
    if (defined $errbuf) {die "Unable to find device: ",$errbuf;}
    print "My device is $device!\n";

    $handle = pcap_open_live($device, 65534, 1, 0, \$errbuf);

    pcap_loop($handle, -1, \&process_packet, "for demo");

    pcap_close($handle);
}

sub process_packet {
    $pack_num++;
    my ($user, $header, $packet)=@_;
    my ($struct,$description)=stackwalk(\$packet,0,1);
	my ($tcp_status,$layer)=&determine_tcp($struct);
	if ($tcp_status==1 and ($$struct{$layer}{'header'}{'src_port'}==22 or $$struct{$layer}{'header'}{'dst_port'}==22)) {
		&network_activity_table($description,$$header{'caplen'},$$header{'tv_sec'});
	}
	if ($pack_num % 100 == 0) {
		&print_status_table;
	}
}

sub print_status_table {
	print $clear;
	my $time=time();
	foreach my $desc (sort keys %status) {
		if ($time - $status{$desc}{'time'} > $timeout) {
			delete($status{$desc});
			print "Removed $desc\n";
		}
		else {
			print "$desc - $status{$desc}{'count'} - $status{$desc}{'size'}\n";
		}
	}
	#pcap_stats($handle,\%cap_stats);
}

sub network_activity_table {
	my ($desc,$size,$time)=@_;
	$status{$desc}{'size'}+=$size;
	$status{$desc}{'time'}=$time;
	$status{$desc}{'count'}++;
}

sub determine_tcp {
	my $struct=shift;
	foreach my $layer (keys %{$struct}) {
		if ($$struct{$layer}{'name'} eq "TCP") {
			return(1,$layer);
		}
	}
	return(0,0);
}




