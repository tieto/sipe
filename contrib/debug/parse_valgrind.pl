#!/usr/bin/perl -w
use 5.010;
use strict;
use warnings;

###############################################################################
#
# Build SIPE with:
#
#  CFLAGS="-g -O0" ./configure
#
# Grab a log with:
#
#  G_DEBUG="gc-friendly" G_SLICE="always-malloc" valgrind --leak-check=yes \
#     /usr/bin/pidgin --debug 2>&1 | tee pidgin_debug.log
#
# Analyze log with:
#
#  perl contrib/debug/parse_valgrind.pl pidgin_debug.log
#
###############################################################################
my @heap_lines;
my @last_heap_lines;
my $invalid_lines;
my @all_invalid_lines;
my $other_lines;

# For all lines from command line files or STDIN
while (<>) {
    next unless my($remainder) = /^==\d+== (.*)/;

    if ($remainder eq "HEAP SUMMARY:") {
	@heap_lines = ($remainder);

	undef $invalid_lines;
	undef $other_lines;

    } elsif ($remainder =~ /^ERROR SUMMARY:/) {
	# keep only the last heap summary
	@last_heap_lines = @heap_lines;

	undef @heap_lines;

    } elsif ($remainder =~ /^Invalid /) {
	# collect all invalid lines
	push(@all_invalid_lines, $remainder);

	undef @heap_lines;
	$invalid_lines++;
	undef $other_lines;

    } elsif ($remainder =~ /^Conditional/) {
	undef @heap_lines;
	undef $invalid_lines;
	$other_lines++

    } elsif (@heap_lines) {
	push(@heap_lines, $remainder);

    } elsif (defined($invalid_lines)) {
	push(@all_invalid_lines, $remainder);

    } elsif (defined($other_lines)) {
	undef $other_lines if $remainder eq "";

    } else {
	#print "UNKNOWN: $remainder\n";
    }
}

sub check_blocks($$$) {
    my($label, $start, $lines) = @_;
    my @block;
    my $flagged;

    print "$label:\n\n";
    foreach (@{$lines}) {
	if (/$start/../^$/) {
	    push(@block, $_);

	    # matcher for SIPE code lines
	    $flagged++
		if /\((?:sipe-|sip-|sdpmsg|sipmsg|http-|uuid|purple-|telepathy-)/;

	    if (length($_) == 0) {
		print join("\n", @block), "\n\n" if $flagged;
		undef @block;
		undef $flagged;
	    }
	}
    }
}

check_blocks("INVALID ACCESSES", qr/^Invalid /, \@all_invalid_lines);
check_blocks("MEMORY LEAKS", qr/^\d+ bytes in \d+ blocks/, \@last_heap_lines);

# That's all folks...
exit 0;
