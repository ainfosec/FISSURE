--
-- This file was generated using: ./smqueue/smqueue --gensql
-- binary version: release 3.1TRUNK built May 22 2013 rev5554M 
--
-- Future changes should not be put in this file directly but
-- rather in the program's ConfigurationKey schema.
--
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS CONFIG ( KEYSTRING TEXT UNIQUE NOT NULL, VALUESTRING TEXT, STATIC INTEGER DEFAULT 0, OPTIONAL INTEGER DEFAULT 0, COMMENTS TEXT DEFAULT '');
INSERT OR IGNORE INTO "CONFIG" VALUES('Asterisk.address','127.0.0.1:5060',0,0,'The Asterisk/SIP PBX IP address and port.');
INSERT OR IGNORE INTO "CONFIG" VALUES('Bounce.Code','101',0,0,'The short code that bounced messages originate from.');
INSERT OR IGNORE INTO "CONFIG" VALUES('Bounce.Message.IMSILookupFailed','Cannot determine return address; bouncing message.  Text your phone number to 101 to register and try again.',0,0,'The bounce message that is sent when the originating IMSI cannot be verified.');
INSERT OR IGNORE INTO "CONFIG" VALUES('Bounce.Message.NotRegistered','Phone not registered here.',0,0,'Bounce message indicating that the destination phone is not registered.');
INSERT OR IGNORE INTO "CONFIG" VALUES('CDRFile','/var/lib/smq.cdr',0,0,'Log CDRs here.  To enable, specify an absolute path to where the CDRs should be logged.  To disable, execute "unconfig CDRFile".');
INSERT OR IGNORE INTO "CONFIG" VALUES('Control.NumSQLTries','3',0,0,'Number of times to retry SQL queries before declaring a database access failure.');
INSERT OR IGNORE INTO "CONFIG" VALUES('Debug.print_as_we_validate','0',0,0,'1=enabled, 0=disabled - Generate lots of output during validation.');
INSERT OR IGNORE INTO "CONFIG" VALUES('Log.Alarms.Max','20',0,0,'Maximum number of alarms to remember inside the application.');
INSERT OR IGNORE INTO "CONFIG" VALUES('Log.File','',0,0,'Path to use for textfile based logging.  By default, this feature is disabled.  To enable, specify an absolute path to the file you wish to use, eg: /tmp/my-debug.log.  To disable again, execute "unconfig Log.File".');
INSERT OR IGNORE INTO "CONFIG" VALUES('Log.Level','NOTICE',0,0,'Default logging level when no other level is defined for a file.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.Balance.Code','1000',0,0,'Short code to the application which tells the sender their current account balance.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.Balance.String','Your account balance is %d',0,0,'Balance message string.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.DebugDump.Code','2336',0,0,'Short code to the application which dumps debug information to the log.  Intended for administrator use.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.Info.Code','411',0,0,'Short code to the application which tells the sender their own number and registration status.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.QuickChk.Code','2337',0,0,'Short code to the application which tells the sender the how many messages are currently queued.  Intended for administrator use.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.Register.Code','101',0,0,'Short code to the application which registers the sender to the system.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.Register.Digits.Max','12',0,0,'The maximum number of digits a phone number can have.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.Register.Digits.Min','4',0,0,'The minimum number of digits a phone number must have.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.Register.Digits.Override','0',0,0,'1=enabled, 0=disabled - Ignore phone number digit length checks.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.Register.Msg.AlreadyA','Your phone is already registered as',0,0,'First part of message sent during registration if the handset is already registered, followed by the current handset number.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.Register.Msg.AlreadyB','.',0,0,'Second part of message sent during registration if the handset is already registered.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.Register.Msg.ErrorA','Error in assigning',0,0,'First part of message sent during registration if the handset fails to register, followed by the attempted handset number.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.Register.Msg.ErrorB','to IMSI',0,0,'Second part of message sent during registration if the handset fails to register, followed by the handset IMSI.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.Register.Msg.TakenA','The phone number',0,0,'First part of message sent during registration if the handset fails to register because the desired number is already taken, followed by the attempted handset number.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.Register.Msg.TakenB','is already in use. Try another, then call that one to talk to whoever took yours.',0,0,'Second part of message sent during registration if the handset fails to register because the desired number is already taken.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.Register.Msg.WelcomeA','Hello',0,0,'First part of message sent during registration if the handset registers successfully, followed by the assigned handset number.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.Register.Msg.WelcomeB','! Text to 411 for system status.',0,0,'Second part of message sent during registration if the handset registers successfully.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.SMSC.Code','smsc',0,0,'The SMSC entry point. There is where OpenBTS sends SIP MESSAGES to.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.WhiplashQuit.Code','314158',0,0,'Short code to the application which will make the server quit for valgrind leak checking.  Intended for developer use only.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.WhiplashQuit.Password','Snidely',0,0,'Password which must be sent in the message to the application at SC.WhiplashQuit.Code.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.WhiplashQuit.SaveFile','testsave.txt',0,0,'Contents of the queue will be dumped to this file when SC.WhiplashQuit.Code is activated.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.ZapQueued.Code','2338',0,0,'Short code to the application which will remove a message from the queue, by its tag.  If first char is "-", do not reply, just do it.  If argument is SC.ZapQueued.Password, then delete any queued message with timeout greater than 5000 seconds.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SC.ZapQueued.Password','6000',0,0,'Password which must be sent in the message to the application at SC.ZapQueued.Code.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SIP.Default.BTSPort','5062',0,0,'The default BTS port to try when none is available.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SIP.GlobalRelay.ContentType','application/vnd.3gpp.sms',1,0,'The content type that the global relay expects.  Static.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SIP.GlobalRelay.IP','',1,0,'IP address of global relay to send unresolvable messages to.  By default, this is disabled.  To override, specify an IP address.  To disable again use "unconfig SIP.GlobalRelay.IP".  Static.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SIP.GlobalRelay.Port','',1,0,'Port of global relay to send unresolvable messages to.  Static.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SIP.GlobalRelay.RelaxedVerify','0',1,0,'1=enabled, 0=disabled - Relax relay verification by only using SIP Header.  Static.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SIP.Timeout.ACKedMessageResend','60',0,0,'Number of seconds to delay resending ACK messages.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SIP.Timeout.MessageBounce','120',1,0,'Timeout, in seconds, between bounced message sending tries.  Static.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SIP.Timeout.MessageResend','120',1,0,'Timeout, in seconds, between message sending tries.  Static.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SIP.myIP','127.0.0.1',0,0,'The internal IP address. Usually 127.0.0.1.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SIP.myIP2','192.168.0.100',0,0,'The external IP address that is communciated to the SIP endpoints.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SIP.myPort','5063',0,0,'The port that smqueue should bind to.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SMS.FakeSrcSMSC','0000',0,0,'Use this to fill in L4 SMSC address in SMS delivery.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SMS.HTTPGateway.Retries','5',0,0,'Maximum retries for HTTP gateway attempt.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SMS.HTTPGateway.Timeout','5',0,0,'Timeout for HTTP gateway attempt in seconds.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SMS.HTTPGateway.URL','',0,0,'URL for HTTP API.  Used directly as a C format string with two "%s" substitutions.  First "%s" gets replaced with the destination number.  Second "%s" gets replaced with the URL-endcoded message body.');
INSERT OR IGNORE INTO "CONFIG" VALUES('ServiceType.Local','in-network-SMS',0,0,'Rate service name for in-network SMS messages.');
INSERT OR IGNORE INTO "CONFIG" VALUES('ServiceType.Networked','out-of-network-SMS',0,0,'Rate service name for out-of-network SMS messages.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SubscriberRegistry.A3A8','../comp128',0,0,'Path to the program that implements the A3/A8 algorithm.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SubscriberRegistry.Manager.Title','Subscriber Registry',0,0,'Title text to be displayed on the subscriber registry manager.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SubscriberRegistry.Manager.VisibleColumns','name username type context host',0,0,'A space separated list of columns to display in the subscriber registry manager.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SubscriberRegistry.Port','5064',0,0,'Port used by the SIP Authentication Server. NOTE: In some older releases (pre-2.8.1) this is called SIP.myPort.');
INSERT OR IGNORE INTO "CONFIG" VALUES('SubscriberRegistry.UpstreamServer','',0,0,'URL of the subscriber registry HTTP interface on the upstream server.  By default, this feature is disabled.  To enable, specify a server URL eg: http://localhost/cgi/subreg.cgi.  To disable again, execute "unconfig SubscriberRegistry.UpstreamServer".');
INSERT OR IGNORE INTO "CONFIG" VALUES('SubscriberRegistry.db','/var/lib/asterisk/sqlite3dir/sqlite3.db',0,0,'The location of the sqlite3 database holding the subscriber registry.');
INSERT OR IGNORE INTO "CONFIG" VALUES('savefile','/tmp/save',0,0,'The file to save SMS messages to when exiting.');
INSERT OR IGNORE INTO "CONFIG" VALUES('Backup.db', '/tmp/smq.backup.db',0,0,'The backup database for SMQ messages');
COMMIT;
