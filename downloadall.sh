#!/bin/bash
wget https://iotanalytics.unsw.edu.au/iottestbed/pcap/filelist.txt -O filelist.txt
cat filelist.txt | egrep -v "(^#.*|^$)" | xargs -n 1 wget
