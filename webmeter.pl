#!/usr/bin/env perl

use strict;
use Net::PcapUtils;
use NetPacket::Ethernet;
use NetPacket::IP;
use List::Util qw(any sum);
use POSIX      qw(strftime ceil);
use Term::ReadKey;

my ( $term_columns, $term_rows ) = GetTerminalSize();

my %imem    = ();
my %omem    = ();
my @gmem    = ();
my @tmem    = ();
my $pkt_max = 2147483647;

my $verbose = find_argv("--verbose");
my $a       = f_primary_adapter();
my $mac     = f_adapter_mac($a);

my $wm_prfx = "[WEBMETER]";
my $hl      = "─";
my $vl      = "│";
my $ltc     = "┌";
my $rtc     = "┐";
my $lbc     = "└";
my $rbc     = "┘";
my $fill    = "█";
my $void    = "░";
my $up      = "△";
my $down    = "▽";

my $reverted_bg = "\e[47m";
my $reverted_fg = "\e[30m";
my $red_fg      = "\e[31m";
my $yellow_fg   = "\e[33m";
my $green_fg    = "\e[32m";
my $reset       = "\e[0m";

my $max_term_rows    = $term_rows > 30    ? 30 : $term_rows;
my $max_term_columns = $term_columns > 70 ? 70 : $term_columns;
my $c_len            = $max_term_columns;
my $r_len            = 12;
my $pkt_threshold    = 100;

sub gmem_max_pkt {

    if ( scalar @gmem == 0 ) {
        return 0;
    }

    my $max = $gmem[0]->{pkt_len};
    foreach my $pkt (@gmem) {
        if ( $pkt->{pkt_len} > $max ) {
            $max = $pkt->{pkt_len};
        }
    }
    return $max;
}

sub gmem_min_pkt {

    if ( scalar @gmem == 0 ) {
        return 0;
    }

    my $min = $gmem[0]->{pkt_len};
    foreach my $pkt (@gmem) {
        if ( $pkt->{pkt_len} < $min ) {
            $min = $pkt->{pkt_len};
        }
    }
    return $min;
}

sub gmem_push {
    my ( $time, $src_mac, $dest_mac, $pkt_len, $inbound ) = @_;
    my %r_hash = (
        time     => $time,
        src_mac  => $src_mac,
        dest_mac => $dest_mac,
        pkt_len  => $pkt_len,
        inbound  => $inbound
    );

    push @gmem, \%r_hash;

    if ( scalar @gmem > $c_len ) {
        shift @gmem;
    }
}

sub r_graph {
    my ( $a, $verbose ) = @_;
    my $min   = gmem_min_pkt();
    my $max   = gmem_max_pkt();
    my $range = $max - $min;

    my %rmap     = ();
    my $rmap_ref = \%rmap;

    for ( my $i = 0 ; $i < scalar @gmem ; $i++ ) {
        my $pkt = $gmem[$i];

        $rmap_ref->{$i} =
          $r_len -
          ceil( normalize( $pkt->{pkt_len}, $min, $max, $r_len - 2 ) ) - 1;
    }

    cls();

    for my $r ( 0 .. $r_len - 1 ) {
        if ( $r == 0 ) {    #first row
            for my $i ( 0 .. $c_len - 1 ) {
                if ( $i == 0 ) {
                    print($ltc);
                }
                elsif ( $i == $c_len - 1 ) {
                    print($rtc);
                }
                else {
                    print($hl);
                }
            }

            print("\n");
        }
        elsif ( $r == $r_len - 1 ) {    #last row
            for my $i ( 0 .. $c_len - 1 ) {
                if ( $i == 0 ) {
                    print($lbc);
                }
                elsif ( $i == $c_len - 1 ) {
                    print($rbc);
                }
                else {
                    print($hl);
                }
            }

            print("\n");
        }
        else {
            for my $i ( 0 .. $c_len - 1 ) {
                if ( $i == 0 || $i == $c_len - 1 ) {
                    print($vl);
                }
                else {
                    my $r_val = $rmap_ref->{$i};

                    if ( defined $r_val and $r_val == $r ) {
                        print($fill);
                    }
                    else {
                        print($void);

                    }
                }
            }

            print("\n");
        }

    }

    my $gmem_len    = scalar @gmem;
    my $tmem_len    = scalar @tmem;
    my $r_threshold = $max_term_rows - $r_len - 2;
    my $si          = $gmem_len > $r_threshold ? $gmem_len - $r_threshold : 0;
    my $traffic     = format_bytelen( sum(@tmem) );
    print
"$reverted_bg$reverted_fg$wm_prfx $a | Traffic $traffic | Packets $tmem_len $reset\n";

    if ($verbose) {
        for my $i ( $si .. $gmem_len - 1 ) {
            my $mem = $gmem[$i];
            if ( !$mem ) {
                continue;
            }
            print( $mem->{time} );
            print(" ");
            print( $mem->{inbound} ? $down : $up );
            print(" ");
            print( format_bytelen( $mem->{pkt_len} ) );

            print("\n");
        }
    }
}

sub find_argv {
    my ($param) = @_;

    for my $arg (@ARGV) {
        if ( $arg eq $param ) {
            return 1;
        }
    }

    return 0;
}

sub format_bytelen {
    my ($byte_len) = @_;

    if ( !defined $byte_len ) {
        return "0b";
    }

    my @classes = ( 'b', 'kB', 'mB', 'gB' );

    my $i = 0;

    while ( $byte_len >= 1024 && $i < scalar @classes ) {
        $byte_len /= 1024;
        $i++;
    }
    if ( $classes[$i] eq $classes[0] ) {
        return sprintf( "%d%s", $byte_len, $classes[$i] );
    }
    return sprintf( "%.2f%s", $byte_len, $classes[$i] );
}

sub normalize {
    my ( $dp, $imin, $imax, $range ) = @_;

    my $x1 = $dp - $imin;
    my $x2 = $imax - $imin;

    if ( $x1 == 0 or $x2 == 0 ) {
        return 0;
    }
    return ( $x1 / $x2 ) * $range;
}

sub cls {
    if ( $^O eq "MSWin32" ) {
        return system("cls");
    }
    return system("clear");
}

sub verify_root {
    if ( $< != 0 ) {
        print
          "$wm_prfx Being root might be required to monitor network adapters\n";
    }
}

sub f_primary_adapter {
    my $a = Net::Pcap::pcap_lookupdev( \my $e );
    if ($e) {
        die "$wm_prfx Cannot find primary network adapter $e\n";
    }
    return $a;
}

sub f_adapter_mac {

    my ($a) = @_;

    my $ifconfig = qx/ifconfig $a/;

    my ($mac) = $ifconfig =~ /(?:ether|HWaddr)\s+([\da-fA-F:]{17})/;

    if ( !defined $mac || !$mac ) {
        die "$wm_prfx Could not determine the adapter's mac address\n";
    }

    $mac =~ s/://g;
    return $mac;
}

sub process_pkt {
    my ( $d, $hdr, $pkt ) = @_;
    my $eth      = NetPacket::Ethernet->decode($pkt);
    my $ip       = NetPacket::IP->decode( NetPacket::Ethernet::strip($pkt) );
    my $ip_data  = $ip->{data};
    my $pkt_len  = $hdr->{len};
    my $time     = strftime( "%Y-%m-%d %H:%M:%S", localtime(time) );
    my $src_mac  = $eth->{src_mac};
    my $dest_mac = $eth->{dest_mac};
    my $inbound  = 0;
    push @tmem, $pkt_len;

    if ( $dest_mac eq $mac ) {

        # inbound mem
        $inbound = 1;
    }
    elsif ( $src_mac eq $mac ) {

        # outbound mem
        $inbound = 0;
    }

    gmem_push( $time, $src_mac, $dest_mac, $pkt_len, $inbound );

    if ( scalar @tmem % 3 == 0 ) {
        r_graph( $a, $verbose );
    }
}

sub main {
    verify_root();

    my $pcap = Net::Pcap::pcap_open_live( $a, $pkt_max, 1, 0, \my $e );

    if ($e) {
        die "$wm_prfx Could not monitor adapter $e\n";
    }

    r_graph( $a, $verbose );

    Net::PcapUtils::loop(
        \&process_pkt,
        SNAPLEN => $pkt_max,
        PROMISC => 1,
        DEV     => $a,
    );

    Net::Pcap::close($pcap);
}

main();
