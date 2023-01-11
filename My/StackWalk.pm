package My::StackWalk;

# This is a module to handle the reading of the pcap and its structure.  Basically the global header and the packet headers.

use Exporter qw(import);

our @EXPORT_OK=qw(stackwalk);

my %link_layer = (
    "1" => \&ethernet,
);

sub stackwalk {
    my $payload=shift;
    my $location=shift;
    my $dlt=shift;
    if (exists($link_layer{$dlt})) {
        $link_layer{$dlt}($payload,$location); 
    }
}

sub ethernet {
    my $payload=shift;
    my $location=shift;
    my %eth=();
    $eth{'dest_mac'} = join(':',unpack("(H2)*",substr($$payload,0,6)));
    $eth{'source_mac'} = join(':',unpack("(H2)*",substr($$payload,6,6)));
    $eth{'ether_type'} = unpack("H*",substr($$payload,12,2));
    print "I made it in here with this mac: $eth{'dest_mac'}\n"; 
}
