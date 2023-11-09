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
my $handle;
my $timeout=60;
my %tcp_sess=();
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
	#if ($tcp_status==1 and ($$struct{$layer}{'header'}{'flags'}==2 or $$struct{$layer}{'header'}{'flags'}%2==1)) {
	if ($tcp_status==1) {
		if ($$struct{$layer}{'header'}{'flags'}==2 or $$struct{$layer}{'header'}{'flags'}==18) {
			my $hdr = pack("LLLL",$$header{'tv_sec'},$$header{'tv_usec'},$$header{'caplen'},$$header{'len'});
			push @{$tcp_sess{$description}},$hdr.$packet;
		}
		elsif ($$struct{$layer}{'header'}{'flags'}%2==1) {
			my $hdr = pack("LLLL",$$header{'tv_sec'},$$header{'tv_usec'},$$header{'caplen'},$$header{'len'});
			push @{$tcp_sess{$description}},$hdr.$packet;
			&write_pcap($description);
		}
		else {
			if (exists($tcp_sess{$description})) {
				my $hdr = pack("LLLL",$$header{'tv_sec'},$$header{'tv_usec'},$$header{'caplen'},$$header{'len'});
				push @{$tcp_sess{$description}},$hdr.$packet;
			}
			else {
				print "Discarding the packet...\n";
			}
		}
	}
}

sub write_pcap {
	my $desc=shift;
	my $flow=$desc;
	my $header = pack("LSSlLLL",0xa1b2c3d4,2,4,0,0,65535,1);
	$desc=~s/\|/-/g;
	$desc=~s/\:/_/g;
	print "going to try and write a file with name - $desc.cap\n";
	open(my $fh,">","/dev/shm/$desc.cap");
	binmode($fh);
	print $fh $header;
	foreach my $packet (@{$tcp_sess{$flow}}) {
		print $fh $packet;
	}
	close($fh);
	delete($tcp_sess{$flow});
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




