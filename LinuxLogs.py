#! /usr/bin/python
#
#  Filename:    LinuxLogs.py
#  Version:     1.0
#  Author:      Carlos Villegas
#               cv127.0.0.1 [at] gmail [dot] com
#
#  Description: It is a tool that consolidates Linux logs of interest to allow the Forensics Investigator the ability to query all events
#               across all logs within a time window (i.e. +/- 3 seconds, user adjustable) around an event. LinuxLogs has the ability to
#               search for a string of interest (i.e. "dirty words", "hit list", black list", etc) because all events are conviniently in a
#               relational database.
#
#               This script was done as a final project for Digital Forensics CS6963 at NYU.edu
#
#               The following Linux logs are processed:
#
#                     '/var/log/dmesg'
#                     '/var/log/messages'
#                     '/var/log/syslog'
#                     '/var/log/auth'
#                     '/var/log/daemon'
#                     '/var/log/dpkg'
#                     '/var/log/kern'
#                     '/var/log/Xorg'
#                     '/var/log/alternatives'
#                     '/var/log/cups'
#                     '/var/log/cron'
#                     '/var/log/wtmp'
#                     '/var/run/utmp'
#                     '/var/log/btmp'
#                     '/var/log/user'
#                     '/var/log/secure'
#                     
#  
#  Notes/Observations:
#
#      1) Future improvements
#         a) Combine the two offset classes
#         b) Refactor RTC related variables out of the parent class and into offset class(es)
#         c) Add support to output query results to .csv format
#         d) Add support for log trending by day/week/month/quarter/year
#         e) Add support for automatic monitoring and saliency trigger and altes
#         d) Add GUI support
#         f) Add support for many many many other logs
#
#      2) Some logs are either binary or encrypted. Their content is accessed in human readable format using the 'last -f /path/to/log' command
#         Those logs are: /var/run/utmp
#                         /var/log/wtmp 
#                         /var/log/btmp
#
#         In addition, the /var/log/btmp requires root privileges for read access on a live system; however, when analyzing logs forensically
#         (from a disk image and extract all files to a directory) the /var/log/btmp log will be read in by this script using the --root option.
#
#      3) The following logs do not have date and/or times in their contents, therefore it is not suitable for the purposes of this script
#         a) /var/log/boot
#         b) /var/log/lastlog
#
#      4) The /var/log/anaconda.log is not used in the Ubuntu Linux distribution which is what I develop in. Therefore it was not included
#         in version 1.0 of this script. However, /var/log/anaconda.log processing will make its way into this script in a future versions.
#
#      5) The log /var/log/faillog was excluded because it provides information already provided by the /var/log/btmp file which is currently
#         a log file that parsed.
#
#
#
#
#
#  Changelog:
#               06/15/2014   Create initial version. Created LinuxLog shell class and tested reading-in all logs
#               06/23/2014   Add support to parse /var/log/dmesg
#               06/24/2014   Add support to normalize time in /var/log/dmesg by using "RTC time: 14:13:21, date: 06/28/14"
#                            along with the event offset i.e. [    0.178863]
#               06/27/2014   Add support for 4 additional types of logs
#               07/03/2014   Desig database tables along with drop/create capabilities
#               07/05/2014   Parsed log data in a db friendly format
#               07/08/2014   Add support to store log file metadata to the parent LOG database table
#               07/12/2014   Add support to store event logs to child LOGEVENTS database table while maintaining the
#                            database relationship between the parent LOG record and the  children records in LOGEVENTS table
#               07/15/2014   Add support for arguments and all options along with their respective arguments if applicable.
#                            Validate all arguments to minimize avoid
#               07/19/2014   Add support for custom root directory other than the default Linux root directory, '/'. This
#                            feature is essential for Forensic Investigators in which they would extract a disk image
#                            either with a 'dd', a 'tar' or similar commands.
#               07/20/2014   Add support to read each log's archive version which come in two flavors: logname.version and logname.version.gz
#                            The reasoning behind this is to be complete and capture all log events.
#               07/20/2014   Add support to remove duplicates cause by reading in all archived versions of a log
#               07/21/2014   Timing analysis for dmesg log family and made some minor adjustments.
#               07/24/2014   Added support for utmp, wtmp and btmp logs
#
#
#
#



# The following is a list of libraries this program uses
from __future__ import print_function
import gc
import os
import re
import sys
from sys import stdout
import glob
import gzip
import sets
import time
import types
from datetime import datetime, date
import datetime
import sqlite3
import logging
import argparse
import subprocess



# -- Parent LogReaderStdParser classes --------------------------------------------------------------------------------------------
class LogReaderStdParser:
    """This class knows how to parse log entries in the format below and defines common methods to all log readers.
    Instantiate for all logs log entires are of the format:
    
        'Jul 11 17:54:32 <servername> <LogEntrySource>: <LogEntryDescription>'
         
    For example:
    
        'Jul 11 17:54:32 SpiderMan kernel: imklog 5.8.11, log source = /proc/kmsg started.'
    """


    def __init__(self, logName, logLocationAbsolutePath, logDescription):
        """Constructor for the LogReader class and all inherited classes
        @param: string - The name of the log
        @param: string - The absolute path to the log (i.e. '/log/var/dmesg')
        @param: string - The description of the log"""
        
        global db
        self.logName = logName
        self.logLocationAbsolutePath = logLocationAbsolutePath
        self.logDescription = logDescription
        self.count = 0
        self.parentRecordID = db.createParentRecord(self.logName, self.logLocationAbsolutePath, self.logDescription)
        self.events = set()
        self.readLogFile()
        self.saveEventsToDB()


    def readLogFile(self):
        """Reads the log entires form the log file (and all its dirivitives i.e. auth.log, auth.log.1, auth.log.2.gz, etc), parses it and saves it to the database"""

        filenamePattern = self.logLocationAbsolutePath+"*"

        for file in glob.glob(filenamePattern):
            # we have a new files, so need to reset RTC because RTCs are relative to one file they are in
            self.waitingForRTC = True; 
            self.preRTC = []
            c=0
            try:
                if( file.endswith('.gz')):
                    with gzip.open(file) as file_object:
                        for line in file_object:
                            c+=1
                            print("    [*] {0:>12,} log entires parsed for file: '{1}'.".format(c, file), end="\r")
                            line = line.rstrip() # remove training whitespaces including '\n'
                            self.decode_entry(line)
                else:
                    with open(file) as file_object:
                        for line in file_object:
                            c+=1
                            print("    [*] {0:>12,} log entires parsed for file: '{1}'.".format(c, file), end="\r")
                            line = line.rstrip() # remove training whitespaces including '\n'
                            self.decode_entry(line)
            except Exception, e:
                pass
            else:
                print(" ")


    def getLogName(self):
        """Returns the name of the log"""
        logName = self.logName
        return logName


    def getLoglogLocationAbsolutePath(self):
        """Returns the absolute path of the log"""
        logName = self.logLocationAbsolutePath
        return logName


    def getRecordCount(self):
        """Returns the number of records associated with this log"""
        count = self.count
        return count


    def saveEventsToDB( self ):
        """This method interfaces with db to save the events that have been gathered so far"""
        c=0
        
        try:
            global db
            for logID, eventDateTime, eventDescription in self.events:
                c+=1
                print("[*] saving {0:>8,} unique log entires for the '{1}' system log to 'LinuxLogs.db'".format(c, self.logLocationAbsolutePath), end = "\r")
                #cvcvcvdb.saveEvent( logID, eventDateTime, eventDescription )
        except Exception, e:
            pass
        print("[*] saved {0:>8,} unique log entires for the '{1}' system log to 'LinuxLogs.db'".format(c, self.logLocationAbsolutePath))
        print(" ")
        


    def saveEvent( self, logID, eventDateTime, eventDescription ):
        """save log event to interal 'events' set. Set's unique properties are being used here to avoid possible duplicates introduced by processing archived versions of a log
        @param: datetime - The date and time at which the log event occured
        @param: string - The description of the log event"""
        try:
            self.events.add((logID, eventDateTime, eventDescription))
        except Exception, e:
            pass


    def decode_entry(self, singleLogEntry):
        """This method knows how to parse log entries in the following format:  'Jul 11 17:54:32 <servername> <LogEntrySource>: <LogEntryDescription>'
        @param: string - The log entry (event date/time and description)"""
        eventTime = 0
        eventDescription = ""
        try:
            # format string obtained from https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
            # target data '2014 Jul 11 17:54:32'
            eventTime = datetime.datetime.strptime(str(date.today().year)+ " " + singleLogEntry[:15], "%Y %b %d %H:%M:%S")
            
            #description is after the fourth space
            splitOnSpaces = singleLogEntry.split(' ')
            eventDescription = (' '.join(splitOnSpaces[:4]), ' '.join(splitOnSpaces[4:]))[1]
            self.saveEvent( self.parentRecordID, eventTime, eventDescription)
        except Exception, e:
            pass
        finally:
            return eventTime, eventDescription




# -- LogReaderParser classes --------------------------------------------------------------------------------------------
class LogReaderParserYYYYMMDD(LogReaderStdParser):
    """This class inherits form the LogReaderStdParser class and overwrides the necessary methods
    to parse the log entires of the format:
    Use this class to read all log entires of the format:
        'YYYY-MM-DD HH:MM:SS <LogEntryDescription>'
    For example:
        '2014-07-07 20:00:15 install simplescreenrecorder:i386 <none> 0.3.0-4~ppa1~saucy1'"""
        
    def decode_entry(self, singleLogEntry):
        """This method parses a log entry of the form: 'YYYY-MM-DD HH:MM:SS <LogEntryDescription>'
        @param: string - The log entry (event date/time and description)"""
        try:
            #format string obtained from https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
            eventDescription = singleLogEntry[20:]
            eventTime = datetime.datetime.strptime(singleLogEntry[:19], "%Y-%m-%d %H:%M:%S")
            self.saveEvent( self.parentRecordID, eventTime, eventDescription)
        except Exception, e:
            pass




# -- LogReaderParserTextDate classes --------------------------------------------------------------------------------------------
class LogReaderParserTextYYYYMMDD(LogReaderStdParser):
    """This class inherits form the LogReaderStdParser class and overwrides the necessary methods
    to parse the log entires of the format:
    
        'some-text YYYY-MM-DD HH:MM:SS <LogEntryDescription>'
         
    For example:
    
        'update-alternatives 2014-07-01 15:43:11: link group wish updated to point to /usr/bin/wish8.5'
    """

    def decode_entry(self, singleLogEntry):
        """This method parses a log entry of the form: 'some-text YYYY-MM-DD HH:MM:SS <LogEntryDescription>'
        @param: string - The log entry (event date/time and description)"""
        try:
            splitOnSpaces = singleLogEntry.split(' ')
            eventDescription = ' '.join(splitOnSpaces[3:])
            #format string obtained from https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
            eventTime = datetime.datetime.strptime(splitOnSpaces[1] + ' ' + splitOnSpaces[2][:8], "%Y-%m-%d %H:%M:%S")
            self.saveEvent( self.parentRecordID, eventTime, eventDescription)
        except Exception, e:
            pass


# -- LogReaderParserTextDateInSquareBrackets classes --------------------------------------------------------------------------------------------
class LogReaderParserTextDateInSquareBrackets(LogReaderStdParser):
    """This class inherits form the LogReaderStdParser class and overwrides the necessary methods
    to parse the log entires of the format:
    
    Use this class to read all log entires of the format:
    
        'some-text [MM/MMM/YYYY:HH:MM:SS -UTC] some-text'
         
    For example:
    
        'localhost - - [12/Jul/2014:06:52:52 -0700] "POST / HTTP/1.1" 401 186 Renew-Subscription successful-ok'
    """

    def decode_entry(self, singleLogEntry):
        """This method parses a log entry of the form: 'some-text YYYY-MM-DD HH:MM:SS <LogEntryDescription>'
        @param: string - The log entry (event date/time and description)"""
        try:
            start = singleLogEntry.find('[')
            end =  singleLogEntry.find(']')
            
            eventDescription = singleLogEntry[end+3:]
            #format string obtained from https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
            #target format: '12/Jul/2014:06:52:52'
            eventTime = datetime.datetime.strptime(singleLogEntry[start+1:end-6], "%d/%b/%Y:%H:%M:%S")
            self.saveEvent( self.parentRecordID, eventTime, eventDescription)
        except Exception, e:
            pass


# -- LogReaderOffsetParserDMESG classes --------------------------------------------------------------------------------------------
class LogReaderOffsetParserDMESG(LogReaderStdParser):
    """This class inherits form the LogReaderStdParser class but overwrides the necessary methods to parse logs that are
    offset-based instead of date-time based as in the parent class.
    
    Use this class to read all log entires of the format:
    
        '[ offset sec]  <LogEntrySource>: <LogEntryDescription>'
         
    For example:
    
        '[    0.178426] RTC time: 22:01:31, date: 07/10/14           <-- notice RTC time comes in eventually!'
    """


    def __init__(self, logName, logLocationAbsolutePath, logDescription):
        """Constructor for the class that knows how to parse the /var/log/dmesg log, this is a child class of LogReaderOffsetParserDMESG
        @param: string - The name of the log
        @param: string - The absolute path to the log (i.e. '/log/var/dmesg')
        @param: string - The description of the log
        """
        self.waitingForRTC = True
        self.RTC = 0
        self.preRTC = []
        LogReaderStdParser.__init__(self, logName, logLocationAbsolutePath, logDescription)


    def extractTimeFromLogEntry(self, singleLogEntry):
        """ extract offset and description and store them into a preRTS list as a temporarily holding structure
        until we read-in RTC which will enable us to convert from offset to evnet time
        @param: string - The description of a log entry"""

        endOfseconds = singleLogEntry.find("]")
        
        # note: Rounding is more appropriate for our case than truncating
        try:
            offsetSecondsSincePowerOn = int( round( float(singleLogEntry[1:endOfseconds]) ) )
        except Exception, e:
            offsetSecondsSincePowerOn = 0
        return offsetSecondsSincePowerOn


    def decode_entry(self, singleLogEntry):
        """This method normalizees time in /var/log/dmesg by using "RTC time: 14:13:21, date: 06/28/14
        @param: string - The description of a log entry"""
        if( self.waitingForRTC == True ):
            #look for RTC
            foundRTCat = singleLogEntry.find("RTC time:")  
            if( foundRTCat != -1 ):
                # if did found clock time then store it for future events, and use it to calculate event
                # timestamps of all previously stored event logs in 'preRTC' list this will put us up-to-date 
                self.RTCstr = singleLogEntry[ foundRTCat+10: ]
                if( self.RTCstr[0]==' '):
                    self.RTCstr = self.RTCstr.lstrip()
                    self.RTCstr = "0"+self.RTCstr
                try:
                    #format string obtained from https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
                    self.RTC = datetime.datetime.strptime(self.RTCstr, "%H:%M:%S, date: %m/%d/%y")
                    self.waitingForRTC = False;
                    self.saveEvent( self.parentRecordID, self.RTC, singleLogEntry[foundRTCat:])

                    # adjust/normalize from offset to local time
                    for item in self.preRTC:
                        eventTime = self.RTC + datetime.timedelta(0, item[0])
                        self.saveEvent( self.parentRecordID, eventTime, item[1])
                    # empty the preRTC because all items have been saved and reset it for the next possible log file within this log family
                    self.preRTC = []
                except Exception, e:
                    pass
            else:
                # extract offset and description and store them into a preRTS list as a temporarily holding structure
                # until we read-in RTC which will enable us to convert from offset to evnet time
                endOfseconds = singleLogEntry.find("]")
                eventDescription = singleLogEntry[endOfseconds+2:]
                
                # note: Rounding is more precise if we want to query on a plus or minus windows in seconds
                offsetSecondsSincePowerOn = self.extractTimeFromLogEntry( singleLogEntry )
                self.preRTC.append( [offsetSecondsSincePowerOn, eventDescription])
        else:
            #if already have clock, then use it to calculate time of log entry
            eventDescription = singleLogEntry[singleLogEntry.find("]")+2:]
            offsetSecondsSincePowerOn = self.extractTimeFromLogEntry( singleLogEntry )
            eventTime = self.RTC + datetime.timedelta(0,offsetSecondsSincePowerOn)
            self.saveEvent(self.parentRecordID, eventTime, eventDescription)
        pass







# -- dbLogs classes --------------------------------------------------------------------------------------------
class dbLogs(object):
    """Class encapsulates all direcect interface to the database"""

    def __init__(self, **kwargs):
        """Standard class constructor"""
        self.connection = sqlite3.connect('LinuxLogs.db')
        self.cursor = self.connection.cursor()


    def createDBitems(self):
        """Method that creates necessary tables and indices"""
        try:
            self.cursor.execute("""
                CREATE TABLE LOGS ( 
                    id                   INTEGER PRIMARY KEY,
                    log_file             varchar(60)  NOT NULL,
                    log_name             varchar(30)  NOT NULL,
                    log_description      varchar(400) NOT NULL);
                    """)
        except Exception as e:
            pass

        try:
            self.cursor.execute("""
                CREATE TABLE LOGEVENTS ( 
                    id                   integer PRIMARY KEY AUTOINCREMENT,
                    fk_logid             integer NOT NULL ,
                    event_datetime       datetime NOT NULL,
                    event_description    varchar(400),
                    FOREIGN KEY ( fk_logid ) REFERENCES LOGS( id ) ON DELETE CASCADE ON UPDATE CASCADE);
            """)
        except Exception as e:
            pass

        try:
            self.cursor.execute("""
                    CREATE INDEX idx_LOGEVENTS ON LOGEVENTS ( fk_logid );
            """)
        except Exception as e:
            pass
        finally:
            pass


    def dropDBitems(self):
        """Method to delete tables and indices from database"""
        try:
            self.cursor.execute("DROP INDEX idx_LOGEVENTS;")
        except Exception as e:
            pass

        try:
            self.cursor.execute("DROP TABLE LOGEVENTS;")
        except Exception as e:
            pass

        try:
            self.cursor.execute("DROP TABLE LOGS;")
        except Exception as e:
            pass


    def createParentRecord(self, logName, logLocationAbsolutePath, logDescription):
        """This method adds a record to the LOGS table
        @param: string - absolute path including name of the log
        @param: string - description of the log"""
        
        parentID = 0
        #find new key value for a new parent record
        self.cursor.execute("SELECT MAX(id) FROM LOGS;")
        parentID = self.cursor.fetchone()[0]
        if parentID == None:
            parentID = 1
        else:
            parentID += 1
        print("[*] new parent ID={0} for log: '{1}'".format(parentID, logLocationAbsolutePath))
        try:
            # add parent record
            logDescription = logDescription.replace("'", "")
            sql_statement = "INSERT INTO LOGS (id, log_name, log_file, log_description) VALUES ( {0}, '{1}', '{2}', '{3}');" \
                            .format(parentID, logName, logLocationAbsolutePath, logDescription)
            self.cursor.execute( sql_statement )
            self.connection.commit()
        except Exception as e:
            pass
        finally:
            pass
        
        return parentID


    def saveEvent( self, parentID, eventTime, eventDescription ):
        """This method adds add a record to the LOGS table
        @param: string - absolute path including name of the log
        @param: string - description of the log"""
        try:
            # add child record
            # note: eventTime needs to be a string of this format: yyyy-MM-dd HH:mm:ss
            # format string obtained from https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
            eventDescription = eventDescription.replace("'", "")
            sql_statement = "INSERT INTO LOGEVENTS (fk_logid, event_datetime, event_description) VALUES ( {0}, '{1}', '{2}');" \
                            .format(parentID, eventTime.strftime("%Y-%m-%d %H:%M:%S"), eventDescription)
            self.cursor.execute( sql_statement )
            self.connection.commit()
        except Exception as e:
            pass
        finally:
            pass


    def displayLogContents( self, logID):
        """This method displays every record in LOGEVENTS associated with a log file 
        @param: string - THe LogID associated with all the events you want to see"""
        self.cursor.execute("SELECT id, event_datetime, event_description FROM LOGEVENTS WHERE fk_logid=={0} ORDER BY event_datetime;".format(logID))
        rows = self.cursor.fetchall()
        for eventID, eventDateTime, eventDescription in rows:
            print(eventID, eventDateTime, eventDescription)
        


    def listLogIDs( self ):
        """This method displays all LogIDs only and associated names stored in the 'LinuxLogs.py'"""
        self.cursor.execute("SELECT id, log_file FROM LOGS ORDER BY id;")
        rows = self.cursor.fetchall()
        for logID, logName in rows:
            print(logID, logName)        


    def queryEventsDateTimeWindow( self, startDateTime, endDateTime):
        """This method displays every event accross all Logs that are within the given start and end dates (inclusive)
        @param: datetime - Start date/time of the window you wish events be displayed
        @param: datetime - End date/time of the window you wish events be displayed"""
        queryStr = "SELECT LOGS.id, LOGS.log_name, LOGEVENTS.event_datetime, LOGEVENTS.event_description " +\
                   "FROM LOGS, LOGEVENTS WHERE LOGS.id = LOGEVENTS.fk_logid AND " 
        queryStr = queryStr + "LOGEVENTS.event_datetime >= Datetime('{0}') AND LOGEVENTS.event_datetime <= Datetime('{1}') ".format(startDateTime, endDateTime)
        queryStr = queryStr + "ORDER BY LOGEVENTS.event_datetime;"
        self.cursor.execute( queryStr )
        rows = self.cursor.fetchall()
        for logID, logName, eventDateTime, eventDescription in rows:
            print("{0:>3}  {1:<20}  {2}    {3}".format(logID, logName, eventDateTime, eventDescription))


    def queryEventsSalientStr( self, stringMatch ):
        """Searches the 'LinuxLogs.db' database for all events that contain a string within their description.
        Use 'root' if, for example, you want to search for all events that contain 'root' anywhere within their event description field.
        @param: string - a keyword representing an item from a 'hit list' or 'black list'"""
        queryStr = "SELECT LOGS.id, LOGS.log_name, LOGEVENTS.event_datetime, LOGEVENTS.event_description " +\
                   "FROM LOGS, LOGEVENTS WHERE LOGS.id = LOGEVENTS.fk_logid AND " 
        queryStr = queryStr + "LOGEVENTS.event_description LIKE '%{0}%' ".format(stringMatch)
        queryStr = queryStr + "ORDER BY LOGEVENTS.event_datetime;"
        self.cursor.execute( queryStr )
        rows = self.cursor.fetchall()
        for logID, logName, eventDateTime, eventDescription in rows:
            print("{0:>3}  {1:<20}  {2}    {3}".format(logID, logName, eventDateTime, eventDescription))



# -- LogReaderOffsetParserXORG classes --------------------------------------------------------------------------------------------
class LogReaderOffsetParserXORG(LogReaderStdParser):
    """This class inherits form the LogReaderStdParser class but overwrides the necessary methods to parse logs that are
    offset-based instead of date-time based as in the parent class.
    
    Use this class to read all log entires of the format:
    
        '[ offset sec]  <LogEntrySource>: <LogEntryDescription>'
         
    For example:
    
        [     4.124] (==) Log file: "/var/log/Xorg.0.log", Time: Mon Jul 14 20:48:05 2014   <-- notice RTC time comes in eventually!
    """


    def __init__(self, logName, logLocationAbsolutePath, logDescription):
        """Constructor for the class that knows how to parse the /var/log/dmesg log, this is a child class of LogReaderOffsetParserDMESG
        @param: string - The name of the log
        @param: string - The absolute path to the log (i.e. '/log/var/dmesg')
        @param: string - The description of the log
        """
        self.waitingForRTC = True
        self.RTC = 0
        self.preRTC = []
        LogReaderStdParser.__init__(self, logName, logLocationAbsolutePath, logDescription)


    def extractTimeFromLogEntry(self, singleLogEntry):
        """ extract offset and description and store them into a preRTS list as a temporarily holding structure
        until we read-in RTC which will enable us to convert from offset to evnet time
        @param: string - The description of a log entry"""

        endOfseconds = singleLogEntry.find("]")
        
        # note: Rounding is more appropriate for our case than truncating
        try:
            offsetSecondsSincePowerOn = int( round( float(singleLogEntry[1:endOfseconds]) ) )
        except Exception, e:
            offsetSecondsSincePowerOn = 0
        return offsetSecondsSincePowerOn


    def decode_entry(self, singleLogEntry):
        """This method normalizees time in /var/log/dmesg by using 'Log file: "/var/log/Xorg.0.log", Time: Mon Jul 14 20:48:05 2014'
        @param: string - The description of a log entry"""
        if( self.waitingForRTC == True ):
            #look for RTC
            marker1 = singleLogEntry.find("Log file:")  
            if( marker1 != -1 ):
                foundRTCat = singleLogEntry.find(", Time: ")
                if( foundRTCat!= -1): 
                    
                    # if did found clock time then store it for future events, and use it to calculate event
                    # timestamps of all previously stored event logs in 'preRTC' list this will put us up-to-date 
                    self.RTCstr = singleLogEntry[ foundRTCat+8: ] #this should give us something of the form 'Mon Jul 14 20:48:05 2014' w/o quotes
                    try:
                        #format string obtained from https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
                        self.RTC = datetime.datetime.strptime(self.RTCstr, "%a %b %d %H:%M:%S %Y")
                        self.waitingForRTC = False;
                        self.saveEvent( self.parentRecordID, self.RTC, singleLogEntry[marker1-5:])
    
                        # adjust/normalize from offset to local time
                        for item in self.preRTC:
                            eventTime = self.RTC + datetime.timedelta(0, item[0])
                            self.saveEvent( self.parentRecordID, eventTime, item[1])
                    except Exception, e:
                        pass
            else:
                # extract offset and description and store them into a preRTS list as a temporarily holding structure
                # until we read-in RTC which will enable us to convert from offset to evnet time
                endOfseconds = singleLogEntry.find("]")
                if( endOfseconds!=-1):
                    eventDescription = singleLogEntry[endOfseconds+2:]
                    if( eventDescription!="" ): 
                        # note: Rounding is more precise if we want to query on a plus or minus windows in seconds
                        offsetSecondsSincePowerOn = self.extractTimeFromLogEntry( singleLogEntry )
                        self.preRTC.append( [offsetSecondsSincePowerOn, eventDescription])
        else:
            #if already have clock, then use it to calculate time of log entry
            eventDescription = singleLogEntry[singleLogEntry.find("]")+2:]
            offsetSecondsSincePowerOn = self.extractTimeFromLogEntry( singleLogEntry )
            eventTime = self.RTC + datetime.timedelta(0,offsetSecondsSincePowerOn)
            self.saveEvent(self.parentRecordID, eventTime, eventDescription)
        pass







# -- LogReader_UTMP_WTMP_Parser classes --------------------------------------------------------------------------------------------
class LogReader_UTMP_WTMP_Parser (LogReaderStdParser):
    """This class inherits form the LogReaderStdParser class but overwrides the necessary methods to parse logs that are
    offset-based instead of date-time based as in the parent class.
    The /var/run/utmp file will give you complete picture of users logins at which terminals,
    logouts, system events and current status of the system, system boot time (used by uptime) etc.
    Use 'last -f /var/run/utmp' to view contents.
    The /var/log/wtmp gives historical data of utmp. Use 'last -f /var/log/wtmp' to view contents.
    note: last -f /var/log/wtmp ====  just last
    
    Example 'last' command output:

    carlos   pts/0        :0               Tue Jul 22 20:03   still logged in   
    carlos   pts/1        :0               Tue Jul 22 18:53 - 20:18  (01:25)    
    reboot   system boot  3.11.0-23-generi Tue Jul 22 18:53 - 20:43  (01:50)    
    carlos   pts/3        :0               Tue Jul 22 16:48 - 18:52  (02:03)    
    carlos   pts/3        :0               Mon Jul 21 15:21 - 21:05  (05:44)

    wtmp begins Wed Jul  2 23:30:12 2014 """


    def readLogFile(self):
        """This method reads every line of text of every log files associated with this class"""
        try:
            subprocess_output = subprocess.check_output(["last"]) # note: last -f /var/log/wtmp ====  last
            c=0
            for line in subprocess_output.splitlines():
                c += 1
                print("    [*] {0:>12,} log entires parsed for file: '{1}'.".format(c, file), end="\r")
                self.decode_entry( line )
        except Exception as e:
            pass


    def decode_entry(self, singleLogEntry):
        """This method decodes log entries for the /var/log/wtmp log file"
        @param: string - The a single line in the log containing the date, time and description of the event"""
        try:
            #extract one event only: log-in
            #format string obtained from https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
            eventTime =  datetime.datetime.strptime(singleLogEntry[39:55]+":00 "+str(date.today().year) , "%a %b %d %H:%M:%S %Y") # of the form 'Tue Jul 22 20:03:00 2014'
            self.saveEvent( self.parentRecordID, eventTime, "Log-in: "+singleLogEntry)
    
            if( singleLogEntry.find("still logged in") == -1 ):
                #extract extra event: log-out
                #                                                   'Tue Jul 22'  '20:18'
                eventTime =  datetime.datetime.strptime(singleLogEntry[39:49]+" "+singleLogEntry[58:63]+ ":00 "+str(date.today().year) , "%a %b %d %H:%M:%S %Y") # of the form 'Tue Jul 22 20:03:00 2014'
                self.saveEvent( self.parentRecordID, eventTime, "Log-off: "+singleLogEntry)
        except Exception as e:
            pass
        pass







# -- LogReader_BTMP_Parser classes --------------------------------------------------------------------------------------------
class LogReader_BTMP_Parser(LogReaderStdParser):
    """The /var/log/btmp records only failed login attempts. Use 'last -f /var/log/btmp' to view contents.
    Use 'last -f /var/log/btmp' to view contents. Note: there may be more logs in this family, so use
    a pattern of last -f /var/log/btmp* to select them.
    
    Example 'last -f /var/log/btmp' command output:

    carlos   ssh:notty    localhost        Tue Jul 22 20:04    gone - no logout"""

    def readLogFile(self):
        """This method reads every line of text of every log files associated with this class"""
        filenamePattern = self.logLocationAbsolutePath+"*"
        for file in glob.glob(filenamePattern):
            c=0
            try:
                with open(file) as file_object:
                    for line in file_object:
                        c+=1
                        print("    [*] {0:>12,} log entires parsed for file: '{1}'.".format(c, file), end="\r")
                        line = line.rstrip() # remove training whitespaces including '\n'
                        try:
                            subprocess_output = subprocess.check_output(["last", "-f", file]) 
                            for line in subprocess_output.splitlines():
                                self.decode_entry( line )
                        except Exception as e:
                            pass
            except Exception, e:
                pass
            else:
                print(" ")


    def decode_entry(self, singleLogEntry):
        """This method decodes log entries for the /var/log/wtmp log file"
        @param: string - The a single line in the log containing the date, time and description of the event"""
        try:
            #extract one event only: log-in
            #format string obtained from https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
            eventTime =  datetime.datetime.strptime(singleLogEntry[39:55]+":00 "+str(date.today().year) , "%a %b %d %H:%M:%S %Y") # of the form 'Tue Jul 22 20:03:00 2014'
            self.saveEvent( self.parentRecordID, eventTime, "Faild login: "+singleLogEntry)
        except Exception as e:
            pass
        pass







#--[ start of main program ]-----------------------------------------------------------------------------------------------------

db = dbLogs() # this instantiates the database object

def readLogs( customRootDir="" ):
    """Use a list to instantiate and hold all our log objects
    @param: string - the argument passed-in by the '--rootDir' option which will be the common way for Forensic Investigators to use this script """
    
    # create filepath variables that take into account, if applicable, the argument passed-in by the '--rootDir' option
    # which will be the common way for Forensic Investigators to use this script 
    filepath_dmesg        = "{0}/var/log/dmesg".format(customRootDir)
    filepath_cron         = "{0}/var/log/cron".format(customRootDir)
    filepath_messages     = "{0}/var/log/messages".format(customRootDir)
    filepath_syslog       = "{0}/var/log/syslog".format(customRootDir)
    filepath_auth         = "{0}/var/log/auth".format(customRootDir)
    filepath_dpkg         = "{0}/var/log/dpkg".format(customRootDir)
    filepath_kern         = "{0}/var/log/kern".format(customRootDir)
    filepath_deamon       = "{0}/var/log/daemon".format(customRootDir)
    filepath_xorg         = "{0}/var/log/Xorg".format(customRootDir)
    filepath_alternatives = "{0}/var/log/alternatives".format(customRootDir)
    filepath_cupsaccess   = "{0}/var/log/cups/access_log".format(customRootDir)
    filepath_utmp_wtmp    = "{0}/var/log/wtmp".format(customRootDir)
    filepath_btmp         = "{0}/var/log/btmp".format(customRootDir)
    filepath_user         = "{0}/var/log/user".format(customRootDir)


    #
    #
    # start instantiating log readers of different kinds, each instantiation
    # parses the log and stores it to the database. Note that the parent class
    # has a few extra helper methods that we are not using, but are available
    # for other developers of this script
    #
    #
    

    LogReaderOffsetParserDMESG( 
        "dmesg log", filepath_dmesg, "Contains kernel ring buffer information. "+ \
        "When the system boots up, it prints number of messages on the screen that "+ \
        "displays information about the hardware devices that the kernel detects "+ \
        "during boot process. These messages are available in kernel ring buffer and "+ \
        "whenever the new message comes the old message gets overwritten. You can also "+ \
        "view the content of this file using the dmesg command.")
        #sample log:
        #$ cat /var/log/dmesg
        #...
        #[    0.177904] PM: Registering ACPI NVS region [mem 0x49f4e000-0x49f54fff] (28672 bytes)
        #[    0.178401] regulator-dummy: no parameters
        #[    0.178426] RTC time: 22:01:31, date: 07/10/14    <-- notice RTC time comes in eventually!
        #[    0.178448] NET: Registered protocol family 16
        #...

    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()



    LogReaderOffsetParserXORG("xorg log", filepath_xorg, "Contains a log of messages from the X"),
        #sample log:
        #$ cat Xorg.0.log
        #...
        #[     4.124] Current version of pixman: 0.30.2
        #[     4.124] Before reporting problems, check http://wiki.x.org
        #[     4.124] Markers: (--) probed, (**) from config file, (==) default setting,
        #[     4.124] (==) Log file: "/var/log/Xorg.0.log", Time: Mon Jul 14 20:48:05 2014   <-- notice RTC time comes in eventually!
        #[     4.124] (==) Using config file: "/etc/X11/xorg.conf"
        #[     4.124] (==) Using system config directory "/usr/share/X11/xorg.conf.d"
    
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()



    logReader = LogReaderStdParser(
        "messages log", filepath_messages, "Contains global system messages, "+ \
        "including the messages that are logged during system startup. Several "+ \
        "things are in this log, such as: mail, cron, daemon, kern, auth, etc."),
        #sample log:
        #$ head /var/log/messages
        #Jul 11 17:54:32 SpiderMan kernel: imklog 5.8.11, log source = /proc/kmsg started.
        #Jul 11 17:54:32 SpiderMan rsyslogd: [origin software="rsyslogd" swVersion="5.8.11" x-pid="8532" x-info="http://www.rsyslog.com"] start
        #Jul 11 17:54:32 SpiderMan rsyslogd: rsyslogd's groupid changed to 103
        #Jul 11 17:54:32 SpiderMan rsyslogd: rsyslogd's userid changed to 101
        
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()



    logReader = LogReaderStdParser(
        "syslog log", filepath_syslog, "Syslog is a way for network devices to send "+ \
        "event messages to a logging server, usually known as a Syslog server. Most "+ \
        "network equipment, like routers and switches, can send Syslog messages. Not only "+ \
        "that, but *nix servers also have the ability to generate Syslog data, as do most "+ \
        "firewalls, some printers, and even web-servers like Apache. "),
        #sample log:
        #$ head /var/log/syslog
        #Jun 29 07:39:42 SpiderMan rsyslogd: [origin software="rsyslogd" swVersion="5.8.11" x-pid="580" x-info="http://www.rsyslog.com"] rsyslogd was HUPed
        #Jun 29 07:39:48 SpiderMan anacron[11496]: Job `cron.daily' terminated
        #Jun 29 07:39:48 SpiderMan anacron[11496]: Normal exit (1 job run)
        #Jun 29 07:43:36 SpiderMan whoopsie[978]: online
    
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()



    logReader = LogReaderStdParser(
        "auth log", filepath_auth, "Contains system authorization information, "+ \
        "including user logins and authentication machinsm that were used."),
        #sample log:
        #$ head /var/log/auth.log
        #Jul 11 17:53:22 SpiderMan sudo: pam_unix(sudo:session): session opened for user root by carlos(uid=0)
        #Jul 11 17:54:32 SpiderMan sudo:   carlos : TTY=pts/3 ; PWD=/home/carlos ; USER=root ; COMMAND=/sbin/restart rsyslog
        #Jul 11 17:54:32 SpiderMan sudo: pam_unix(sudo:session): session opened for user root by carlos(uid=0)
        #Jul 11 18:34:59 SpiderMan dbus[507]: [system] Rejected send message, 3 matched rules; type="method_return", sender=":1.66" (uid=1000 pid=2090 comm="/usr/bin/pulseaudio --start --log-target=syslog ") interface="(unset)" member="(unset)" error name="(unset)" requested_reply="0" destination=":1.2" (uid=0 pid=622 comm="/usr/sbin/bluetoothd ")
    
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()



    logReader = LogReaderParserYYYYMMDD(
        "dpkg log", filepath_dpkg, "Records all the apt activities, such as installs "+ \
        "or upgrades, for the various package managers (dpkg, apt-get, synaptic, aptitude)."),
        #sample log:
        #$ head /var/log/dpkg.log
        #2014-07-04 16:55:36 trigproc desktop-file-utils:i386 0.21-1ubuntu3 0.21-1ubuntu3
        #2014-07-04 16:55:36 status half-configured desktop-file-utils:i386 0.21-1ubuntu3
        #2014-07-04 16:55:36 status installed desktop-file-utils:i386 0.21-1ubuntu3
        #2014-07-04 16:55:36 trigproc gnome-menus:i386 3.8.0-1ubuntu5 3.8.0-1ubuntu5
    
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()



    logReader = LogReaderStdParser(
        "kern log", filepath_kern, "Contains information logged by the kernel. "+ \
        "Helpful for you to troubleshoot a custom-built kernel."),
        #sample log:
        #$ head /var/log/kern.log
        #Jul 10 15:01:36 SpiderMan kernel: [    5.052266] wlan0: authenticate with 10:bf:48:53:c7:90
        #Jul 10 15:01:36 SpiderMan kernel: [    5.055880] wlan0: send auth to 10:bf:48:53:c7:90 (try 1/3)
        #Jul 10 15:01:36 SpiderMan kernel: [    5.058578] wlan0: authenticated
        #Jul 10 15:01:36 SpiderMan kernel: [    5.058631] wlan0: waiting for beacon from 10:bf:48:53:c7:90
        #Jul 10 15:01:36 SpiderMan kernel: [    5.109448] wlan0: associate with 10:bf:48:53:c7:90 (try 1/3)
        #Jul 10 15:01:36 SpiderMan kernel: [    5.112845] wlan0: RX AssocResp from 10:bf:48:53:c7:90 (capab=0x411 status=0 aid=4)
        #Jul 10 15:01:36 SpiderMan kernel: [    5.114950] wlan0: associated
    
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()



    logReader = LogReaderStdParser(
        "cron log", filepath_cron, "Whenever cron daemon (or anacron) starts a cron job, it "+ \
        "logs the information about the cron job in this file"),
        #sample log:
        #$ head /var/log/cron.log
        #Jul 12 08:17:01 SpiderMan CRON[5040]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
    
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()



    logReader = LogReaderStdParser(
        "daemon log", filepath_deamon, "Contains information logged by the "+ \
        "various background daemons that runs on the system"),
        #sample log:
        #$ head /var/log/daemon.log
        #Jul 12 08:04:20  whoopsie[1020]: last message repeated 4 times
        #Jul 12 08:05:20  whoopsie[1020]: last message repeated 2 times
        #Jul 12 08:09:02 SpiderMan whoopsie[1020]: online
        #Jul 12 08:15:16  whoopsie[1020]: last message repeated 5 times
    
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()



    logReader = LogReaderParserTextYYYYMMDD(
        "alternatives log", filepath_alternatives, "Information by the "+ \
        "update-alternatives are logged into this log file. On Ubuntu, update-alternatives "+ \
        "maintains symbolic links determining default commands."),
        #sample log:
        #$ head /var/log/alternatives.log
        #update-alternatives 2014-07-01 15:43:11: link group tclsh updated to point to /usr/bin/tclsh8.5
        #update-alternatives 2014-07-01 15:43:11: link group wish updated to point to /usr/bin/wish8.5
        #update-alternatives 2014-07-02 23:29:03: run with --remove x-www-browser /usr/bin/chromium-browser
        #update-alternatives 2014-07-04 07:53:48: link group mailx updated to point to /usr/bin/heirloom-mailx
    
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()



    logReader = LogReaderParserTextDateInSquareBrackets(
        "cups access log", filepath_cupsaccess, "The access_log file lists each HTTP resource that "+ \
        "is accessed by a web browser or client. Each line is in an extended version of the so-called 'Common "+ \
        "Log Format' used by many web servers and web reporting tools")
        #sample log:
        #$ head /var/log/cups/access_log
        #localhost - - [12/Jul/2014:06:52:52 -0700] "POST / HTTP/1.1" 401 186 Renew-Subscription successful-ok
        #localhost - carlos [12/Jul/2014:06:52:52 -0700] "POST / HTTP/1.1" 200 186 Renew-Subscription successful-ok
        #localhost - - [12/Jul/2014:07:06:52 -0700] "POST / HTTP/1.1" 401 186 Renew-Subscription successful-ok
        #localhost - carlos [12/Jul/2014:07:06:52 -0700] "POST / HTTP/1.1" 200 186 Renew-Subscription successful-ok
    
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()


    logReader = LogReaderStdParser(
        "user log", filepath_user, "Contains information about all user level logs")
        #sample log:
        #$ head /var/log/cups/access_log
        #Jul 20 12:23:50 SpiderMan mtp-probe: bus: 3, device: 8 was not an MTP device
        #Jul 21 18:10:31 SpiderMan pulseaudio[2114]: [bluetooth] bluetooth-util.c: Failed to release transport /org/bluez/656/hci0/dev_00_0C_8A_6E_0E_B5/fd10: Method "Release" with signature "s" on interface "org.bluez.MediaTransport" doesn't exist
        #Jul 22 18:53:07 SpiderMan mtp-probe: checking bus 3, device 6: "/sys/devices/pci0000:00/0000:00:14.0/usb3/3-9/3-9.1"
        #Jul 22 18:53:12 SpiderMan pulseaudio[1845]: [pulseaudio] pid.c: Daemon already running.
    
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()


    logReader = LogReader_UTMP_WTMP_Parser(
        "utmp & wtmp logs", filepath_utmp_wtmp, "The /var/run/utmp file will give you " +\
        "complete picture of users logins at which terminals, logouts, system events and " +\
        "current status of the system, system boot time (used by uptime) etc. Use 'last " +
        "\-f /var/run/utmp' to view contents. The /var/log/wtmp gives historical data of utmp ")
        #sampel log:
        #$ last -f /var/log/wtmp
        #
        #carlos   pts/0        :0               Tue Jul 22 20:03   still logged in   
        #carlos   pts/1        :0               Tue Jul 22 18:53 - 20:18  (01:25)    
        #reboot   system boot  3.11.0-23-generi Tue Jul 22 18:53 - 20:43  (01:50)    
        #carlos   pts/3        :0               Tue Jul 22 16:48 - 18:52  (02:03)    
        #carlos   pts/3        :0               Mon Jul 21 15:21 - 21:05  (05:44)
        #
        #wtmp begins Wed Jul  2 23:30:12 2014 """

    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()


    logReader = LogReader_BTMP_Parser(
        "btmp log", filepath_btmp, "The /var/log/btmp records only failed login attempts. " +\
        "Use 'last -f /var/log/btmp' to view contents. Use 'last -f /var/log/btmp' to view " +\
        "contents. Note: there may be more logs in this family, so use a pattern of last  " +\
        "-f /var/log/btmp* to select them.")
    
    #deallocate/release memory that we do not need anymore
    logReader = 0
    gc.collect()


def databaseReset():
    """
    This function will cause the database to be wiped out, tables and indicies dropped, recreated and reset to a clean slate
    """
    db.dropDBitems()
    db.createDBitems()


def main(argv):
    """Main's responsibility to accepts to parse arguments and carry-out user's choices."""

    # reference: https://docs.python.org/2/howto/argparse.html
    parser = argparse.ArgumentParser(description='Linux System Logs Analysis for Digital Forensics by Carlos Villegas')
    parser.add_argument("--resetDB",              help="Causes database to be wiped and logs to be re-read.",  action='store_true') #optional
    parser.add_argument("--contents",             help="Display contents of 'LinuxLogs.db' of one log specified by LogID",
                                                        type=int, metavar="logID")  #optional w/argument
    parser.add_argument("--query",                help="Searches the 'LinuxLogs.db' database for all events within +/- window of N seconds "+\
                                                       "from a specific date/tiem. The'dateTimeStr' should be of this format 'YYYY-MM-DD hh:mm:ss, N' "+\
                                                       "with quotes. For example: '2014-02-19 19:07:05, 3' to list all events across all logs in "+\
                                                       "the database in between '2014-02-19 19:07:02' and '2014-02-19 19:07:08' (inclusive).", \
                                                       type=str, metavar="dateTimeStr")  #optional w/argument
    parser.add_argument("--logs",                 help="Lists all LogIDs and associated LogNames stored in 'LinuxLogs.db'", action='store_true')  #optional
    parser.add_argument("--rootDir",              help="Intended audience: Forensics Investigators. Use this when you have extracted a Linux " +\
                                                       "disk image to a directory of your choice. An absolute path that you have read permissions " +\
                                                       "must be given.  WARNING: this will cause the 'LinuxLogs.db' database to be wiped and logs " +\
                                                       "to be re-read within the new root directory. For example: if you extracted the disk image " +\
                                                       "to a subdirectory inside your home directory called 'forensicTree', then you should use " +\
                                                       "'/home/yourname/forensicsTree'", \
                                                       type=str, metavar="newRootDir")  #optional w/argument
    parser.add_argument("--stringMatch",          help="Searches the 'LinuxLogs.db' database for all events that contain a string within their "+\
                                                       "description. Use 'root' if, for example, you want to search for all events that contain "+\
                                                       "'root' anywhere within their event description field.", \
                                                       type=str, metavar="descriptionStr")  #optional w/argument

    try:
        args=parser.parse_args()
    except Exception, e:
        pass

    if( args.resetDB ):
        print("[*] resetDB detected")
        databaseReset()
        readLogs()

    if( args.logs ):
        print("[*] logs detected")
        db.listLogIDs()

    if( args.contents!=None ):
        print("[*] contents with LogID={0} detected".format(args.contents))
        db.displayLogContents(args.contents)

    if( args.query!=None ):
        print("[*] query with datetimeStr='{0}' detected".format(args.query))
        #validate input
        formatAccepted = False
        splitQueryStr = args.query.split(',')
        try:
            parsedDateTime = datetime.datetime.strptime(splitQueryStr[0], "%Y-%m-%d %H:%M:%S")
        except Exception, e:
            print("Opps! The DATE-TIME part of the query string you typed does not conform to the format: 'YYYY-MM-DD hh:mm:ss', please try again.")
        else:
            try:
                isInteger = isinstance( int(splitQueryStr[1]), (int, long))
            except Exception, e:
                print("Opps! The 'N' part of the query string you typed was not recognized and an integer, please try again.")
            else:
                print("[*]format accepted")
                #compute START-of-window-datetime and END-of-window-datetime
                try:
                    startOfWindow = parsedDateTime - datetime.timedelta(0, int(splitQueryStr[1]))
                    endOfWindow   = parsedDateTime + datetime.timedelta(0, int(splitQueryStr[1]))
                    print("[*]startOfWindow = '{0}' to endOfWindow = '{1}'".format(str(startOfWindow), str(endOfWindow)))
                    db.queryEventsDateTimeWindow( startOfWindow, endOfWindow)
                except Exception, e:
                    pass

    if( args.stringMatch!=None ):
        print("[*] query with stringMatch='{0}' detected".format(args.stringMatch))
        db.queryEventsSalientStr( args.stringMatch )

    if( args.rootDir!=None):
        print("[*] rootDir detected with '{0}'".format(args.rootDir))
        databaseReset()
        readLogs(args.rootDir)

    if( args.resetDB==False and
        args.logs==False and
        args.contents==None and
        args.query==None and
        args.stringMatch==None and
        args.rootDir==None ):
        
        print("[*] no options detected. Please type 'LinuxLogs.py --help' for help on how to use this script.\n\nUSER GUIDE:\n\n" +\
              "If you are a Forensic Investigator, \n\n" +\
              "     these are the steps you must to do in the order specified:\n\n" +\
              "     1. Extract all files within a disk image to a subdirectory, for example, extract them to FooBarDir\n\n" +\
              "     2. Have this script read, parse and store logs into the 'LinuxLogs.db' database\n" +\
              "        use this command:  $python LinuxLogs.py --rootDir 'FooBarDir' \n\n" +\
              
              "If you are a Network Security person or System Administrator,\n\n" +\
              "     You must do this step first:\n\n" +\
              "     1. Have this script read, parse and store logs into the 'LinuxLogs.db' database\n" +\
              "        preferably run this as root:  $sudo python LinuxLogs.py --resetDB \n" +\
              "        (running the above command with root privileges will give you read access to /var/log/btmp log file)\n\n" +\

              "Once the database is populated (see above), you can do any or all following in any order you want any number of times:\n\n" +\
              "     A. Query which logs were parsed and stored into the 'LinuxLogs.db' database'\n" +\
              "        use this command:  $python LinuxLogs.py --logs \n\n" +\
              "     B. Query an entire log to display all events associated with only one logID that are store in the 'LinuxLogs.db' database'\n" +\
              "        use this command:  $python LinuxLogs.py --contents 8 \n\n" +\
              "     C. Query the 'LinuxLogs.db' database for all events accross all logs that occured the within a date/time window'\n" +\
              "        use this command:  $python LinuxLogs.py --query '2014-07-24 17:45:06, 2000' \n\n" +\
              "     D. Quey the 'LinuxLogs.db' database for all events that contain a string of interest within their description field.\n"+\
              "        use this command:  $python LinuxLogs.py --stringMatch 'chown' \n")


if __name__ == '__main__':
   main(sys.argv)
