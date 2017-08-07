#!/usr/bin/perl -w
#
# @file SipeHelper.pm
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
# Support code for D-Bus test scripts
#
package SipeHelper;
use 5.024;
use strict;
use warnings;

use Carp;
use Net::DBus;

# Connect to libpurple over the session bus
my $purple;
sub init()
{
    eval {
	my $bus     = Net::DBus->session;
	my $service = $bus->get_service('im.pidgin.purple.PurpleService');
	$purple     = $service->get_object('/im/pidgin/purple/PurpleObject',
					   'im.pidgin.purple.PurpleInterface');
    };
    die "ERROR: can't find any active libpurple D-Bus instance, Are you sure you started Pidgin/Finch?\n\n$@"
	if $@;
}

# Call code reference for all active SIPE accounts
sub forSipeAccounts($)
{
    my($code) = @_;
    croak "ERROR: ${code} should be code reference"
	unless ref($code) eq "CODE";
    croak "ERROR: called without initializing"
	unless $purple;

    # Get list of enabled accounts
    my $accounts = $purple->PurpleAccountsGetAllActive();
    for my $accountId (@{ $accounts }) {
	my $username     = $purple->PurpleAccountGetUsername($accountId);
	my $protocolId   = $purple->PurpleAccountGetProtocolId($accountId);
	my $protocolName = $purple->PurpleAccountGetProtocolName($accountId);
	my $connectionId = $purple->PurpleAccountGetConnection($accountId);
	print "found account ${accountId}: ${username} (${protocolId}/${protocolName}, ${connectionId})\n";

	# Filter out SIPE accounts that are online
	if (($protocolId eq 'prpl-sipe') && ($connectionId != 0)) {

	    # Filter out SIPE accounts that are really connected
	    if ($purple->PurpleConnectionIsConnected($connectionId)) {

		# Call code reference
		$code->($purple, $accountId, $username);
	    }
	}
    }
}

# modules need to return a true value
1;
