package My::StackWalk;

# This is a module to handle the reading of the pcap and its structure.  Basically the global header and the packet headers.

use Exporter qw(import);

our @EXPORT_OK=qw(stackwalk);

my %link_layer = (
    "1" => \&ethernet,
);

my %layer_2 = (
    "0800" => \&ip,
    "8847" => \&mpls,
);

my %layer_3 = (
    6   => \&tcp,
    17  => \&udp,
);

sub stackwalk {
    my $payload=shift;
    my $location=shift;
    my $dlt=shift;
    my $layer=0;
    my %struct=();
    if (exists($link_layer{$dlt})) {
        $link_layer{$dlt}($payload,$location,\%struct,$layer);
    }
    return \%struct;
}

sub tcp {
    my $payload=shift;
    my $location=shift;
    my $struct=shift;
    my $layer=shift;
    $layer++;
    my %tcp=();
}

sub udp {
    my $payload=shift;
    my $location=shift;
    my $struct=shift;
    my $layer=shift;
    $layer++;
    my %udp=();
    ($udp{'source'},$udp{'dest'},$udp{'length'})=unpack("nnn",substr($$payload,$location,6));
    $udp{'payload'}=substr($$payload,$location+8);
    $$struct{$layer}{'name'}="UDP";
    $$struct{$layer}{'header'}=\%udp;
}

sub ethernet {
    my $payload=shift;
    my $location=shift;
    my $struct=shift;
    my $layer=shift;
    $layer++;
    my %eth=();
    $eth{'dest_mac'} = join(':',unpack("(H2)*",substr($$payload,$location,6)));
    $eth{'source_mac'} = join(':',unpack("(H2)*",substr($$payload,$location+6,6)));
    $eth{'ether_type'} = unpack("H*",substr($$payload,$location+12,2));
    $location+=14;
    $$struct{$layer}{'name'}="Ethernet";
    $$struct{$layer}{'header'}=\%eth;
    if (exists($layer_2{$eth{'ether_type'}})) {
        $$struct{$layer}{'info'}="$eth{'source_mac'}-$eth{'dest_mac'}";
        $layer_2{$eth{'ether_type'}}($payload,$location,$struct,$layer);
    }
    else {
        $$struct{$layer}{'info'}="$eth{'source_mac'}-$eth{'dest_mac'}|$eth{'ether_type'}-NextLayerUnknown";
    }

}

sub mpls {

}

sub ip {
    my $payload=shift;
    my $location=shift;
    my $struct=shift;
    my $layer=shift;
    $layer++;
    my %ip=();
    my $first_byte = unpack("B*",substr($$payload,$location,1));
    $ip{'version'}=oct("0b".substr($first_byte,0,4));
    $ip{'header_length'}=(oct("0b".substr($first_byte,4,4)) * 4);
    $ip{'total_length'}=unpack("n",substr($$payload,$location+2,2));
    $ip{'id'}=unpack("H*",substr($$payload,$location+4,2));
    $ip{'ttl'}=unpack("c",substr($$payload,$location+8,1));
    $ip{'protocol'}=unpack("c",substr($$payload,$location+9,1));
    $ip{'source'}=unpack("L",substr($$payload,$location+12,4));
    $ip{'destination'}=unpack("L",substr($$payload,$location+16,4));
    $location+=$ip{'header_length'};
    $$struct{$layer}{'name'}="IP";
    $$struct{$layer}{'header'}=\%ip;

    if (exists($layer_3{$ip{'protocol'}})) {
        $$struct{$layer}{'info'}="D$ip{'source'}D$ip{'destination'}";
        $layer_3{$ip{'protocol'}}($payload,$location,$struct,$layer);
    }
    else {
        $$struct{$layer}{'info'}="D$ip{'source'}D$ip{'destination'}|$ip{'protocol'}-NextLayerUnknown";
    }
     
}
