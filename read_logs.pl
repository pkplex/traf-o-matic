#!/usr/bin/perl
use strict;

my $argc = $#ARGV + 1;
if ($argc <= 0) {
    print "log directory not specified\n";
    exit;
}
my $log_dir = $ARGV[0];

my @FILES = <$log_dir/*>;

map { &parse($_); } @FILES;

# parse a single file (file name given as argument) and tally up the traffic.
sub parse ()
{
    my $fname = $_[0];
    
    if (!open(FILE, "<$fname")) {
        print "failed to open $fname\n";
        return;
    }
    
    my $low_epoc = 0;
    my $high_epoc = 0;
    my $tx = 0;
    my $rx = 0;

    while (<FILE>) {
        if (my ($epoc, $out, $in) = ($_ =~ /(\d+)\s+(\d+)\s+(\d+)/)) {
            $tx += $out;
            $rx += $in;
            # record the timeframe (start, end) of this logfile.
            if ($epoc < $low_epoc or $low_epoc == 0) { $low_epoc = $epoc; }
            if ($epoc > $high_epoc or $high_epoc == 0) { $high_epoc = $epoc; }
        }
    }

    if ($low_epoc == 0 or $high_epoc == 0) {
        return;
    }

    my $bleh = sprintf("%.2f MB out, %.2f MB in" , ($tx / 1024 / 1024), ($rx / 1024 / 1024));
    print "$fname: $bleh\n";
    # different output format...
    # print "$fname: " . localtime($low_epoc) 
    #     . " to " 
    #     . localtime($high_epoc) 
    #     . " $bleh\n";

    return;
}

