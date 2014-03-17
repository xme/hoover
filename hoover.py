#!/usr/bin/env python

import threading
import signal
import sys
import time
import subprocess
import os

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
                 
        
# create switch thread
#switchThread = switchChannelThread(1, 'SwitchChannel', 'airbase', 14, 5)
#switchThread.start()

osname = os.uname()[0]

tsharkPath = '/usr/local/bin/tshark'

displayFilter = "wlan.fcs_good==1 and not wlan_mgt.ssid==\\\"\\\"";
fieldParams = "-T fields -e wlan.sa -e wlan_mgt.ssid -Eseparator=,";
tsharkCommandLine = "{0} -i en1 -n -l {1}"

if (osname == 'Darwin'):
    tsharkCommandLine += " subtype probereq -2 -R \"{2}\""
else:
	tsharkCommandLine += " -y PPI -2 -R \"wlan.fc.type_subtype==4 and {2}\""

tsharkCommandLine = tsharkCommandLine.format(tsharkPath, fieldParams, displayFilter)

print 'tshark command: %s' % tsharkCommandLine, 

popen = subprocess.Popen(tsharkCommandLine, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
for line in iter(popen.stdout.readline, ''): 
    print 'line: %s' % (line,)
    
signal.signal(signal.SIGINT, signal_handler)
print 'press CTRL+C'
signal.pause()