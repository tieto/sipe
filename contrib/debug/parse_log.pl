#!/usr/bin/perl -w
use 5.010;
use strict;
use warnings;

# For all lines from command line files or STDIN
my @message;
while (<>) {

  # Start of message?
  if (my ($direction, $type, $time) =
      /^MESSAGE START\s+([<>]+)\s+(\S+)\s+-\s+(.+)/) {
    push(@message,
	 "------------- NEXT MESSAGE: " .
	 (($direction =~ /^>/) ? "outgoing" : "incoming") .
	 " $type at $time\n");

  # End of message?
  } elsif (/^MESSAGE END/) {

    # @TODO: do something with the message
    print @message;

    # Done with the current message
    undef @message;

  # All other lines
  } else {

    # Collect message information
    push(@message, $_) if @message;
  }
}

# That's all folks...
exit 0;
