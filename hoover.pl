#!/usr/bin/perl
#
# hoover.pl - Wi-Fi probe requests sniffer
#
# Original idea by David Nelissen (twitter.com/davidnelissen)
# Thank to him for allowing me to reuse the idea!
#
# This script scans for wireless probe requests and prints them out.
# Hereby you can see for which SSID's devices nearby are searching.
#
# Copyright (c) 2012 David Nelissen & Xavier Mertens
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of copyright holders nor the names of its
#    contributors may be used to endorse or promote products derived
#    from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL COPYRIGHT HOLDERS OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# History
# -------
# 2012/01/11	Created
#

use strict;
use Getopt::Long;

$SIG{USR1}	= \&dumpNetworks; # Catch SIGINT to dump the detected networks
$SIG{INT}	= \&cleanKill;
$SIG{KILL}	= \&cleanKill;
$SIG{TERM}	= \&cleanKill;

my $uniqueSSID = 0;		#uniq ssid counter
my %detectedSSID;	# Detected network will be stored in a hash table
			# SSID, Seen packets, MAC, Last timestamp
my $pid;
my $help;
my $verbose;
my $interface;
my $dumpFile;
my $osname = $^O;
my $ifconfigPath = "/sbin/ifconfig";
my $iwconfigPath = "/sbin/iwconfig";
my $airportPath  = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";
my $tsharkPath   = "/usr/local/bin/tshark";
my $options = GetOptions(
	"verbose"		=> \$verbose,
	"help"			=> \$help,
	"interface=s"		=> \$interface,
	"ifconfig-path=s"	=> \$ifconfigPath,
	"iwconfig-path=s"	=> \$iwconfigPath,
	"tshark-path=s"		=> \$tsharkPath,
	"dumpfile=s"		=> \$dumpFile,
);

if ($help) {
	print <<_HELP_;
Usage: $0 --interface=en1_or_wlan0 [--help] [--verbose] [--iwconfig-path=/sbin/iwconfig] [--ipconfig-path=/sbin/ifconfig]
		[--dumpfile=result.txt]
Where:
--interface		: Specify the wireless interface to use
--help			: This help
--verbose		: Verbose output to STDOUT
--ifconfig-path		: Path to your ifconfig binary
--iwconfig-path		: Path to your iwconfig binary
--tshark-path		: Path to your tshark binary
--dumpfile		: Save found SSID's/MAC addresses in a flat file (SIGUSR1)
_HELP_
	exit 0;
}

# We must be run by root
($< != 0) && die "$0 must be run by root!\n";

# We must have an interface to listen to
(!$interface) && die "No wireless interface speficied!\n";

# Check ifconfig availability
( ! -x $ifconfigPath) && die "ifconfig tool not found!\n";

# Check iwconfig availability
($osname ne 'darwin') && ( ! -x $iwconfigPath) && die "iwconfig tool not found!\n";

# Check tshark availability
( ! -x $tsharkPath) && die "tshark tool not available!\n";

# Configure wireless interface
(system("$ifconfigPath $interface up")) && "Cannot initialize interface $interface!\n";

# Set interface in monitor mode
($osname ne 'darwin') && (system("$iwconfigPath $interface mode monitor")) && die "Cannot set interface $interface in monitoring mode!\n";
($osname eq 'darwin') && (system("$airportPath $interface -z")) && die "Cannot disassociate interface $interface!\n";

# Create the child process to change wireless channels
(!defined($pid = fork)) && die "Cannot fork child process!\n";

if ($pid) {
	# ---------------------------------
	# Parent process: run the main loop
	# ---------------------------------
	($verbose) && print "!! Running with PID: $$ (child: $pid)\n";

	# only valid packets and non-empty SSIDs:
	my $displayFilter = "wlan.fcs_good==1 and not wlan_mgt.ssid==\\\"\\\"";
	my $fieldParams = "-T fields -e wlan.sa -e wlan_mgt.ssid -Eseparator=,";
	my $tsharkCommandLine = "$tsharkPath -i $interface -n -l $fieldParams";
	if ($osname ne 'darwin') {
		$tsharkCommandLine .= " subtype probereq -2 -R \"$displayFilter\" |";
	} else {
		$tsharkCommandLine .= " -y PPI -2 -R \"wlan.fc.type_subtype==4 and $displayFilter\" |"
	}
	($verbose) && print "!! command: $tsharkCommandLine\n";

	open(TSHARK, $tsharkCommandLine) || die "Cannot spawn tshark process!\n";
	while (<TSHARK>) {
		chomp;
		my $line = $_;
		chomp($line = $_); 
		my ($macAddress, $ssid) = split(/,/, $line);
		($verbose) && print "!! found packet: mac=$macAddress, ssid=$ssid\n";
		my $hashKey = "$macAddress-$ssid";
		if (! $detectedSSID{$hashKey})
		{
			# New network found!
			my @newSSID = ( $ssid,		# SSID
					1,			# First packet
					$macAddress,		# MAC Address
					time());		# Seen now
			$detectedSSID{$hashKey} = [ @newSSID ];
			$uniqueSSID++;
			print "++ New probe request from $macAddress with SSID: $ssid [$uniqueSSID]\n";
		}
		else
		{
			# Existing SSID found!
			$detectedSSID{$hashKey}[1]++;			# Increase packets counter
			$detectedSSID{$hashKey}[2] = $macAddress;	# MAC Address
			$detectedSSID{$hashKey}[3] = time();		# Now
			($verbose) && print "-- Probe seen before: $hashKey [$uniqueSSID]\n";
		}
	}
}
else {
	# --------------------------------------------------
	# Child process: Switch channels at regular interval
	# --------------------------------------------------
	($verbose) && print STDOUT "!! Switching wireless channel every 5 seconds.\n";
	if ($osname ne 'darwin') {
	  while (1) {
		  for (my $channel = 1; $channel <= 12; $channel++) {
			  ($verbose) && print STDOUT "!! Switching to channel $channel\n";
			  (system("$iwconfigPath $interface channel $channel")) &&
				  die "Cannot set interface channel.\n";
			  sleep(5);
  		}
	  } 
  }
	else {
  	while (1) {
	  	for (my $channel = 1; $channel <= 14; $channel++) {
		  	($verbose) && print STDOUT "!! Switching to channel $channel\n";
			  (system("$airportPath $interface -c$channel")) &&
				  die "Cannot set interface channel.\n";
		  	sleep(5);
		  }
	  } 
  }
}

sub dumpNetworks {
	my $i;
	my $key;
	print STDOUT "!! Dumping detected networks:\n";
	print STDOUT "!! MAC Address          SSID                           Count      Last Seen\n";
	print STDOUT "!! -------------------- ------------------------------ ---------- -------------------\n";
	if ($dumpFile) {
		open(DUMP, ">$dumpFile") || die "Cannot write to $dumpFile (Error: $?)";
		print DUMP "MAC Address          SSID                           Count      Last Seen\n";
		print DUMP "-------------------- ------------------------------ ---------- -------------------\n";
	}
	for $key ( keys %detectedSSID)
	{
		my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($detectedSSID{$key}[3]);
		my $lastSeen = sprintf("%04d/%02d/%02d %02d:%02d:%02d", $year+1900, $mon+1, $mday, $hour, $min, $sec);
		print STDOUT sprintf("!! %-20s %-30s %10s %-20s\n", $detectedSSID{$key}[2],
		 				 $detectedSSID{$key}[0], $detectedSSID{$key}[1], $lastSeen);
		($dumpFile) && print DUMP sprintf("%-20s %-30s %10s %-20s\n", 
						 $detectedSSID{$key}[2], $detectedSSID{$key}[0],
						 $detectedSSID{$key}[1], $lastSeen); 
	}
	print STDOUT "!! Total unique SSID: $uniqueSSID\n";
	($dumpFile) && print DUMP "Total unique SSID: $uniqueSSID\n";
	close(DUMP);
	return;
}

sub cleanKill {
	if ($pid) {
		# Parent process: display information
		print "!! Received kill signal!\n";
		kill 1, $pid;
		dumpNetworks;
	}
	exit 0;
}
