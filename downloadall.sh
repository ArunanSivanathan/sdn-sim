#!/bin/bash
wget http://iotanalytics.unsw.edu.au/iotFiles/filelist.txt -O filelist.txt
cat filelist.txt | egrep -v "(^#.*|^$)" | xargs -n 1 wget
