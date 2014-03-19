#!/usr/bin/env python

import threading
import signal
import sys
import time
import subprocess
import os
import os.path
import argparse



def signal_handler(signal, frame):
    print 'You pressend CTRL+C, data is flushed into database/file...'
    switchThread.running = False
    switchThread.join()
    formatString = "{0: <18} {1: <20} {2: <18}"
    print formatString.format("mac", "ssid", "last seen")
    for key, value in entries.iteritems():
        print formatString.format(value.mac, value.ssid, time.strftime("%Y%m%d-%H:%M:%S", value.timeLastSeen))
    sys.exit(0)


class switchChannelThread (threading.Thread):
    def __init__(self, threadID, name, delayInSeconds):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        if osname != "Darwin":
            self.maxChannel = 12
        else:
            self.maxChannel = 14
        self.delayInSeconds = delayInSeconds
        self.running = True
    def run(self):
        print 'Starting switch channel thread using a dely of %d seconds' % self.delayInSeconds
        while self.running:
            for channel in range (1, self.maxChannel + 1):
                if verbose: 
                    print 'Switching to channel %d' % (channel)
                if osname != "Darwin":
                    if subprocess.call([iwconfigPath, interface, "channel", channel]) != 0:
                        self.running = False
                        sys.exit(4)
                else:
                    if subprocess.call([airportPath, interface, "-c%d" % channel]) != 0:
                        self.running = False
                        sys.exit(4)
                    
                time.sleep(self.delayInSeconds)
                if not self.running:
                    return        

class Entry (object):
    def __init__(self, mac, ssid, time):
        self.mac = mac
        self.ssid = ssid
        self.timeLastSeen = time


osname = os.uname()[0]
if osname != "Darwin":
    defaultInterface = "wlan0"
else:
    defaultInterface = "en1"

# command line parsing:
parser = argparse.ArgumentParser(description='Show and collect wlan request probes')
parser.add_argument('--interface', default=defaultInterface, 
    help='the interface used for monitoring')
parser.add_argument('--tsharkPath', default='/usr/local/bin/tshark', 
    help='path to tshark binary')
parser.add_argument('--ifconfigPath', default='/sbin/ifconfig', 
    help='path to ifconfig')
parser.add_argument('--iwconfigPath', default='/sbin/iwconfig', 
    help='path to iwconfig')
parser.add_argument('--verbose', action='store_true', help='verbose information')
args = parser.parse_args()

tsharkPath = args.tsharkPath
ifconfigPath = args.ifconfigPath
iwconfigPath = args.iwconfigPath
interface = args.interface
verbose = args.verbose

# only on osx:
airportPath = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";

# check all params
if not os.path.isfile(tsharkPath):
    print "tshark not found at path {0}".format(tsharkPath)
    sys.exit(1)
if not os.path.isfile(ifconfigPath):
    print "ifconfig not found at path {0}".format(ifconfigPath)
    sys.exit(1)
if osname != "Darwin":
    if not os.path.isfile(iwconfigPath):
        print "iwconfig not found at path {0}".format(iwconfigPath)
        sys.exit(1)

# start interface
if subprocess.call([ifconfigPath, interface, 'up']) != 0:
    print "cannot start interface: {0}".format(interface)
    sys.exit(2)

# Set interface in monitor mode
retVal = 0
if osname != 'Darwin':
    retVal = subprocess.call([iwconfigPath, interface, "mode", "monitor"])
else:
    retVal = subprocess.call([airportPath, interface, "-z"])

if retVal != 0:
    print "cannot set interface to monitor mode: {0}".format(interface)
    sys.exit(3)

# start thread that switches channels
switchThread = switchChannelThread(1, 'SwitchChannel', 5)
switchThread.start()
signal.signal(signal.SIGINT, signal_handler)
print 'press CTRL+C to exit'
# signal.pause()

# start tshark and read the results
displayFilter = "wlan.fcs_good==1 and not wlan_mgt.ssid==\\\"\\\"";
fieldParams = "-T fields -e wlan.sa -e wlan_mgt.ssid -Eseparator=,";
tsharkCommandLine = "{0} -i {1} -n -l {2}"

if (osname != 'Darwin'):
    tsharkCommandLine += " subtype probereq -2 -R \"{3}\""
else:
	tsharkCommandLine += " -y PPI -2 -R \"wlan.fc.type_subtype==4 and {3}\""

tsharkCommandLine = tsharkCommandLine.format(tsharkPath, interface, fieldParams, displayFilter)

if verbose: 
    print 'tshark command: %s\n' % tsharkCommandLine, 

DEVNULL = open(os.devnull, 'w')
popen = subprocess.Popen(tsharkCommandLine, shell=True, stdout=subprocess.PIPE, stderr=DEVNULL)

# collect all Entry objects in entries
entries = {}

for line in iter(popen.stdout.readline, ''):
    line = line.rstrip()
#    if verbose: 
#        print 'line: "%s"' % (line,)
    if line.find(',') > 0:
        mac, ssid = line.split(',', 1)
        if line in entries:
            if verbose:
                print "entry found (seen before): mac: '{0}', ssid: '{1}'".format(mac,ssid)
            entry = entries[line]
            entry.timeLastSeen = time.localtime()
        else:
            print "new entry found: mac: '{0}', ssid: '{1}'".format(mac,ssid)
            entries[line] = Entry(mac, ssid, time.localtime())
