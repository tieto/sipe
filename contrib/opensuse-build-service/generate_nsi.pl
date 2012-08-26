#!/usr/bin/perl
use 5.008;
use strict;
use warnings;

# check commandline arguments
die "Usage: $0 <LINGUAS file> < nsi-template > nsi-output\n"
    if @ARGV < 1;

# process LINGUAS file
open(my $fh, "<", $ARGV[0])
    or die "$0: can't open LINGUAS file '$ARGV[0]': $!\n";
my %languages = map { ($_, 1) } map { chomp; s/^\s+//; s/\s+$//; $_ } <$fh>;
close($fh)
    or die "$0: error while reading LINGUAS file '$ARGV[0]': $!\n";
print STDERR "Found ", scalar(keys %languages), " language(s): ",
                       join(" ", sort keys %languages), "\n";

# read .nsi template from STDIN
# write .nsi file to STDOUT
while (<STDIN>) {
    if (/^;;; INSTALL_FILES_LOCALE/) {
	print map({
	           ("SetOutPath \"\$INSTDIR\\locale\\$_\\LC_MESSAGES\"\n",
		    "File \"\${MINGW_DATADIR}\\locale\\$_\\LC_MESSAGES\\pidgin-sipe.mo\"\n")
		  } sort keys %languages);
    } elsif (/^;;; DELETE_FILES_LOCALE/) {
	print map({
	           "Delete \"\$INSTDIR\\locale\\$_\\LC_MESSAGES\\pidgin-sipe.mo\"\n"
		  } sort keys %languages);
    } else {
	print;
    }
}

# That's all folks...
exit 0;
