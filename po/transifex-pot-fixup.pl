#!/usr/bin/perl -w
#
# Fix up pidgin-sipe.pot after an update to make it acceptable for Transifex
#
# Transifex update procedure:
#
#    $ cd po
#    $ intltool-update --pot -g pidgin-sipe     # update POT file
#    $ ./transifex-pot-fixup.pl                 # this script
#    $ cd ..
#    $ tx push -s                               # update POT file on Transifex
#
#    [optional: update the languages you know on Transifex]
#
#    $ tx pull -s                               # fetch updated translations
#    $ git add -u po/*.po po/*.pot              # add files to next commit
#    $ git commit -e
#
use 5.008;
use strict;
use warnings;

open(my $fh, "+<", "pidgin-sipe.pot")
  or die "$0: can't open POT file: $!\n";

my $date;
{
  my(undef, $min, $hour, $mday, $mon, $year) = gmtime(time());
  $date = sprintf("%4d-%02d-%02d %02d:%02d+0000",
		  $year + 1900, $mon + 1, $mday, $hour, $min);
}

# Must be 19 lines (same as header created by intltool-update)
my @lines = ( <<"END_OF_HEADER"
# (English) English User Interface strings for pidgin-sipe.
# Copyright (C) 2008-2011 SIPE Project <http://sipe.sourceforge.net/>
# This file is distributed under the same license as the pidgin-sipe package.
# 
# 
# 
msgid ""
msgstr ""
"Project-Id-Version: pidgin sipe\\n"
"Report-Msgid-Bugs-To: http://sourceforge.net/tracker/?group_id=194563&atid=949931\\n"
"POT-Creation-Date: 2010-11-30 23:36+0200\\n"
"PO-Revision-Date: $date\\n"
"Last-Translator: stefanb <chemobejk\@gmail.com>\\n"
"Language-Team: English <LL\@li.org>\\n"
"MIME-Version: 1.0\\n"
"Content-Type: text/plain; charset=UTF-8\\n"
"Content-Transfer-Encoding: 8bit\\n"
"Language: en\\n"
"Plural-Forms: nplurals=2; plural=(n != 1)\\n"
END_OF_HEADER
	    );

while (<$fh>) {
  # skip header
  next if $. < 20;

  push(@lines, $_);
}

# Update pot file
seek($fh, 0, 0)
  or die "$0: can't rewind POT file: $!\n";
print $fh @lines;
close($fh)
  or die "$0: can't write to POT file: $!\n";

# That's all folks
exit 0;
