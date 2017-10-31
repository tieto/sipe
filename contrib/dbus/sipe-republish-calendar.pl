#!/usr/bin/perl -w
#
# @file sipe-republish-calendar.pl
#
# pidgin-sipe
#
# Copyright (C) 2017 SIPE Project <http://sipe.sourceforge.net/>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#
# Test code for D-Bus interface "SipeRepublishCalendar"
#
use 5.024;
use strict;
use warnings;

use FindBin;
use lib $FindBin::Bin;
use SipeHelper;

SipeHelper::init();
SipeHelper::forSipeAccounts(sub {
    my($purple, $accountId, $username) = @_;
    print "Trying to republish calendar data on SIPE account '${username}'...\n";
    $purple->SipeRepublishCalendar($accountId);
});

# That's all folks...
exit 0;
