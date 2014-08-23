Linux-Logs
==========

Audio+Video presentation: http://youtu.be/uxaSTZv5k-8

Slides: https://drive.google.com/file/d/0BwMw6ipu4nPzYlVhSktVWFU3SWM/edit?usp=sharing

Linux Logs is an open source tool developed to assist Forensics Investigators, Network Security folks and 
System Administrators by parsing either live host logs or extracted logs from a forensic disk image and 
consolidating logs of forensic interest into an SQL database to allow Forensics Investigators the ability 
to query all events across all logs within a time window (i.e. +/­ 3 seconds, user adjustable) around a 
forensic event. Since all events are conveniently in a relational database, they can be queried based on 
a string of interest (i.e. "dirty words", "hitlist", black list", etc).

This tool is intended for two types of audiences: 

1) Forensic Investigators – interested in logs extracted form a forensic disk image, so they will need to 
use this tool with the “­­rootDir” option for this tool (see below).

2) Network Security folks and System Administrators – interested in logs from a live host (i.e. the host 
on which this tool is run on), so they will need to use this tool with the “­­resetDB” option.


If you are a Forensic Investigator, these are the steps you must to do in the order specified:

   1. Extract all files within a disk image to a subdirectory, for example, extract them to FooBarDir

   2. Have this script read, parse and store logs into the 'LinuxLogs.db' database

      To do this, you will use this command:  

         $python LinuxLogs.py ­­rootDir 'FooBarDir' 


On the other hand, if you are a Network Security person or System Administrator, you must have this script 
read, parse and store logs into the 'LinuxLogs.db' database preferably run this as root with the command:

      To do this, you will use this command:

         $sudo python LinuxLogs.py ­­resetDB 

      Running the above command with root privileges will give you read access to /var/log/btmp log file.


Once the database is populated, you can do any or all following in any order you want any number of times:

A. Query which logs were parsed and stored into the 'LinuxLogs.db' database'

   use this command:  $python LinuxLogs.py ­­logs 

B. Query an entire log to display all events associated with only one logID that are store in the 'LinuxLogs.db'
   database'

   use this command:  $python LinuxLogs.py ­­contents 8 

C. Query the 'LinuxLogs.db' database for all events accross all logs that occured the within a date/time window'

   use this command:  $python LinuxLogs.py ­­query '2014­07­24 17:45:06, 2000'

D. Quey the 'LinuxLogs.db' database for all events that contain a string of interest within their description field.

   use this command:  $python LinuxLogs.py ­­stringMatch 'chown'


Your feedback is important! 

Please send it to:

Carlos Villegas

cv127.0.0.1+GitHub[at]gmail[dot]com
