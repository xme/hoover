#!/usr/bin/env python

import threading
import signal
import sys
import time
import subprocess
import os
import argparse


def signal_handler(signal, frame):
    print 'You pressend CTRL+C, data is flushed into database/file...'
    switchThread.running = False
    switchThread.join()
    sys.exit(0)


class switchChannelThread (threading.Thread):
    def __init__(self, threadID, name, switchCommand, maxChannel, delayInSeconds):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.switchCommand = switchCommand
        self.maxChannel = maxChannel
        self.delayInSeconds = delayInSeconds
        self.running = True
    def run(self):
        print 'Starting switch channel thread using a dely of %d seconds' % self.delayInSeconds
        while self.running:
            for channel in range (1, self.maxChannel):
                print 'Switching to channel %d' % (channel)
                time.sleep(self.delayInSeconds)
                if not self.running:
                    return        


# command line parsing:
parser = argparse.ArgumentParser(description='Show and collect wlan request probes')
parser.add_argument('--interface', default='en1', 
    help='the interface used for monitoring')
parser.add_argument('--tsharkPath', default='/usr/local/bin/tshark', 
    help='path to tshark binary')
parser.add_argument('--verbose', action='store_true', help='verbose information')
args = parser.parse_args()

tsharkPath = args.tsharkPath
interface = args.interface
verbose = args.verbose

# create switch thread
#switchThread = switchChannelThread(1, 'SwitchChannel', 'airbase', 14, 5)
#switchThread.start()

osname = os.uname()[0]

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

for line in iter(popen.stdout.readline, ''):
    line = line.rstrip()
    if verbose: 
        print 'line: "%s"' % (line,)
    if line.find(',') > 0:
        mac, ssid = line.split(',', 1)
        print "mac: '{0}', ssid: '{1}'".format(mac,ssid)
    
signal.signal(signal.SIGINT, signal_handler)
print 'press CTRL+C'
signal.pause()
