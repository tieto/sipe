#!/usr/bin/perl -w
use 5.010;
use strict;
use warnings;

use File::Spec;
use Getopt::Long;
use Pod::Usage;

# Command line option
my %Options = (
	       directory => ".",
	      );
GetOptions(\%Options,
	   "directory=s",
	   "callid",
	   "from",
	   "method",
	   "filter",
	   "help|h|?")
  or pod2usage(2);
pod2usage(-verbose => 2) if $Options{help};

###############################################################################
#
# Message parsing
#
###############################################################################
my %callid;
my %from;
my %method;
sub AddMessage($$$@)
{
  my($direction, $type, $time, @message) = @_;

  # Only handle SIP for now...
  return unless $type eq "SIP";

  my($index, $callid, $from, $method);
  foreach my $line (@message) {
    next if $index++ < 1;
    last if $line =~ /^\s+$/;

    next unless my($keyword, $value) = $line =~ /^([^:]+):\s+(.+)/;
    $callid   = $value                     if $keyword =~ /^call-id$/i;
    ($from)   = $value =~ /^<sip:([^;>]+)/ if $keyword =~ /^from$/i;
    ($method) = $value =~ /^\d+\s+(\S+)/   if $keyword =~ /^cseq$/i;
  }
  push(@{$callid{$callid}},     \@message) if $Options{callid} && defined $callid;
  push(@{$from{lc($from)}},     \@message) if $Options{from}   && defined $from;
  push(@{$method{uc($method)}}, \@message) if $Options{method} && defined $method;
}

sub DumpMessages()
{
  foreach my $callid (keys %callid) {
    if (open(my $fh, ">",
	     File::Spec->catfile($Options{directory}, "callid-${callid}.txt"))) {
      print $fh @{$_} foreach (@{$callid{$callid}});
      close($fh);
    }
  }
  foreach my $from (keys %from) {
    if (open(my $fh, ">",
	     File::Spec->catfile($Options{directory}, "from-${from}.txt"))) {
      print $fh @{$_} foreach (@{$from{$from}});
      close($fh);
    }
  }
  foreach my $method (keys %method) {
    if (open(my $fh, ">",
	     File::Spec->catfile($Options{directory}, "method-${method}.txt"))) {
      print $fh @{$_} foreach (@{$method{$method}});
      close($fh);
    }
  }
}

###############################################################################
#
# Main program
#
###############################################################################

# For all lines from command line files or STDIN
my @message;
my $counter;
while (<>) {

  # Start of message?
  if (my ($direction, $type, $time) =
      /^MESSAGE START\s+([<>]+)\s+(\S+)\s+-\s+(.+)/) {
    push(@message,
	 "------------- NEXT MESSAGE: " .
	 (($direction =~ /^>/) ? "outgoing" : "incoming") .
	 " $type at $time\n");

  # End of message?
  } elsif (($direction, $type, $time) =
	   /^MESSAGE END\s+([<>]+)\s+(\S+)\s+-\s+(.+)/) {

    if ($Options{filter}) {
      print @message;
    } else {
      print STDERR "." if (++$counter % 10 == 0);
      AddMessage($direction, $type, $time, @message);
    }

    # Done with the current message
    undef @message;

  # All other lines
  } else {

    # Collect message information
    push(@message, $_) if @message;
  }
}

unless ($Options{filter}) {
  print STDERR "\n" unless $Options{filter};
  DumpMessages();
}

# That's all folks...
exit 0;

__END__

=head1 NAME

parse_log.pl - parse pidgin-sipe debug log

=head1 SYNOPSIS

[perl} parse_log.pl --help|-h|-? 

[perl} parse_log.pl --filter
                    [file ...]

[perl} parse_log.pl [--directory <dir>]
                    [--callid]
                    [--from]
                    [--method]
                    [file ...]

=head1 OPTIONS

=over 8

=item B<--callid>

Dump all SIP messages belonging to one Call-ID to the same file.

=item B<--directory>

Directory for output files. Default is the current directory.

=item B<--filter>

Enable filter mode. Messages are simply printed to stdout.

=item B<--from>

Dump all SIP messages sent from the same SIP URI to the same file.

=item B<--help>

=item B<--h>

=item B<--?>

Print a brief help message and exits.

=item B<--method>

Dump all SIP messages with the same method to the same file.

=back

=head1 DESCRIPTION

B<This program> extracts SIP/HTTP messages from pidgin-sipe debug logs. If
no file is specified then it reads from STDIN.

=cut
