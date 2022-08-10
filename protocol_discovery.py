import zmq
import time
import re
import numpy as np
import binascii
from collections import Counter
import time
import random
import yaml
import zmq
import sys
from fissureclass import fissure_listener
from fissureclass import fissure_server
import os   
import threading
from fissure_libutils import *  # import library utilities to read and add things to the library
#import pandas
#from PyQt4 import QtCore, QtGui, uic 
    
#~ alphabetbin = ['0','1']
#~ alphabethex = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
        
# Insert Any Argument While Executing to Run Locally
try:
    run_local = sys.argv[1]
except:
    run_local = None  

class ThreadingCallback(threading.Thread):
    """ Object to spawn off a function into a thread and then return the value back in
        a message on the pub port - Used for running stats on the latest buffer capture and
        returning to the HIPRFISR/Dashboard for user.
    """
    def __init__(self, pd_pub_server,MessageName,mytarget, *targetargs):
        self.pd_pub_server = pd_pub_server
        self.mytarget = mytarget
        self.targetargs = targetargs
        self.MessageName = MessageName
        threading.Thread.__init__(self)
        #threading.Thread.setdaemon(True)
        # setting all as Daemon in case we have non-graceful closeout 
        # (if we're interrupted, the calculations are left unfinished
        # but resources should be fine
 
    def run(self):
        self.returnval = self.mytarget(*self.targetargs)
        self.pd_pub_server.sendmsg('Status', Identifier = 'PD', MessageName = self.MessageName, Parameters=self.returnval)              
        
class ProtocolDiscovery():
    """ Class that contains the functions for protocol discovery.
    """
    
    #######################  FISSURE Functions  ########################
    
    def __init__(self):
        """ The start of Protocol Discovery.
        """
        self.dashboard_connected = False 
        self.hiprfisr_connected = False

        self.heartbeat_interval = 5
        self.pd_heartbeat_time = 0
        self.finding_preambles = False    
        self.lib_search = False
        self.min_size = 4
        self.max_size = 24
        self.ranking = 10  # top number of strings of length between min_size and max_size    
        self.num_std = 2  # find those preambles within 2 std deviations of the mean packet length   
        self.min_buffer = 100    
        self.buffer_size_time = time.time()
        self.flush_buffer = False

        self.pd_library = self.loadLibrary()    
        self.loadConfiguration()   
    
        # Create the PD ZMQ Sockets
        self.connect()
        
        # Main Event Loop
        try:
            while True:
                # Read Messages in the ZMQ Queues
                if self.hiprfisr_connected == True:
                    self.readHIPRFISR_Messages()
                self.readSUB_Messages()
                
                # Send the PD heartbeat if interval time has elapsed
                self.sendHeartbeat()
                                        
                # Check for received heartbeats
                #checkHeartbeats()            
                
                time.sleep(1)

        except KeyboardInterrupt:       
            pass
                        
    def loadLibrary(self):
        """ Loads the protocol library from "library.yaml."
        """
        filename = os.path.dirname(os.path.realpath(__file__)) + '/YAML/library.yaml'
        with open(filename) as yaml_config_file:
            library_loaded = yaml.load(yaml_config_file, yaml.FullLoader)
        return library_loaded        
        
    def connect(self):
        """ Connects all the 0MQ Servers and Listeners 
        """      
        # Create Connections       
        dashboard_ip_address = "127.0.0.1"
        hiprfisr_ip_address = "127.0.0.1"
        pd_ip_address = "127.0.0.1"
        fge_ip_address = "127.0.0.1"
        
        self.bit_ip_address = fge_ip_address
                
        # DEALER
        self.hiprfisr_buffer = ""             
        pd_dealer_port = int(self.settings_dictionary['pd_hiprfisr_dealer_port'])
        self.pd_hiprfisr_listener = fissure_listener(os.path.dirname(os.path.realpath(__file__)) + '/YAML/pd.yaml',hiprfisr_ip_address,pd_dealer_port,zmq.DEALER, logcfg = os.path.dirname(os.path.realpath(__file__)) + "/YAML/logging.yaml", logsource = "pd") 
        
        # PUB       
        pd_pub_port = int(self.settings_dictionary['pd_pub_port'])
        self.pd_pub_server = fissure_server(os.path.dirname(os.path.realpath(__file__)) + '/YAML/pd.yaml',pd_ip_address,pd_pub_port,zmq.PUB, logcfg = os.path.dirname(os.path.realpath(__file__)) + "/YAML/logging.yaml", logsource = "pd")
            
        # SUB   
        dashboard_pub_port = int(self.settings_dictionary['dashboard_pub_port'])
        hiprfisr_pub_port = int(self.settings_dictionary['hiprfisr_pub_port'])
        
        fge_pub_port = int(self.settings_dictionary['fge_pub_port'])

        # PD SUB to HIPRFISR PUB
        try:
            self.pd_sub_listener = fissure_listener(os.path.dirname(os.path.realpath(__file__)) + '/YAML/pd.yaml',hiprfisr_ip_address,hiprfisr_pub_port,zmq.SUB, logcfg = os.path.dirname(os.path.realpath(__file__)) + "/YAML/logging.yaml", logsource = "pd") 
            sub_connected = True
        except:
            print "Error creating PD SUB and connecting to HIPRFISR PUB"
            
        # PD SUB to Dashboard PUB
        try:
            self.pd_sub_listener.initialize_port(dashboard_ip_address,dashboard_pub_port)  # Need to Update IP Address        
        except:
            print "Unable to connect PD SUB to Dashboard PUB"   
            
        # PD SUB to FGE Flow Graph PUB
        pd_bits_port = self.settings_dictionary['pd_bits_port']
        
        try:                       
            context = zmq.Context()
            self.pd_bit_sub_listener = context.socket(zmq.SUB)
    
            self.max_buffer = 2 ** 18  # 200K Buffer for Receiving Bits, Change to Make Bigger for Binary (Rewrite Receiver Function)  
            self.pd_bit_sub_listener.setsockopt(zmq.LINGER,0) 
            
            self.pd_bit_sub_listener.connect("tcp://" + fge_ip_address + ":" + str(pd_bits_port))  # 'localhost' causes issues with FGE Flow Graphs for some reason

            self.pd_bit_sub_listener.setsockopt_string(zmq.SUBSCRIBE,u'')

        except KeyError, e:
            print "Unable to connect PD SUB to FGE PUB"    
            
    def readSUB_Messages(self):
        """ Read all the messages in the pd_sub_listener and handle accordingly.
        """    
        # Check for Messages
        parsed = ''
        while parsed != None:
            parsed = self.pd_sub_listener.recvmsg()   
            if parsed != None: 
                if parsed['Identifier'] == 'Dashboard':
                    self.dashboard_connected = True  # Not Currently Used
                    
                    # Check for the "Exit Connect Loop" Message
                    if parsed['Type'] == 'Status':                                                  
                        # FGE Pushbutton Pressed
                        if parsed['MessageName'] == 'Connect to FGE':
                            self.connectToFGE()                                      
                            
                elif parsed['Identifier'] == 'HIPRFISR':
                    self.hiprfisr_connected = True
                    if parsed['Type'] == 'Status':  
                        if parsed['MessageName'] == 'Full Library':                        
                            self.pd_library = yaml.load(parsed['Parameters'], yaml.FullLoader)    

                # Handle Messages/Execute Callbacks as Usual
                else:
                    if parsed['Type'] == 'Heartbeats':
                        ## Update Stored Heartbeat Time in settings_dictionary
                        #settings_dictionary[parsed['Identifier'].lower() + '_heartbeat_time'] = parsed['Time']
                    
                        ## Update Other Heartbeat Related Variables 
                        pass    

    def readHIPRFISR_Messages(self):
        """ Sort through any HIPRFISR messages.
        """     
        # Check for Messages
        parsed = ''
        while parsed != None:
            parsed = self.pd_hiprfisr_listener.recvmsg()   
            if parsed != None:                              
                # Handle Messages/Execute Callbacks 
                self.pd_hiprfisr_listener.runcallback(self,parsed)  
            
    def sendHeartbeat(self):
        """ Sends the heartbeat to all subscribers.
        """        
        current_time = time.time()
        if self.pd_heartbeat_time < current_time - self.heartbeat_interval:
            self.pd_heartbeat_time = current_time
            self.pd_pub_server.sendmsg('Heartbeats', Identifier = 'PD', MessageName='Heartbeat', Time=current_time)        
            
    def connectToFGE(self):
        """ Reconnects the Protocol Discovery SUB to the FGE Component Flow Graph PUB when the FGE Component is run locally.
        """
        # Remove Connections
        fge_default_ip_address = "127.0.0.1"    
        pd_bits_port = str(self.settings_dictionary['pd_bits_port'])
        self.pd_bit_sub_listener.disconnect('tcp://' + fge_default_ip_address + ':' + pd_bits_port)
        
        # Reconnect
        hiprfisr_default_ip_address = "127.0.0.1" # Locally
        self.bit_ip_address = hiprfisr_default_ip_address
        #~ self.pd_bit_sub_listener.initialize_port(hiprfisr_default_ip_address,pd_bits_port)         
        self.pd_bit_sub_listener.connect("tcp://" + self.bit_ip_address + ":" + pd_bits_port)  # 'localhost' causes issues with FGE Flow Graphs for some reason

    def addPubSocket(self, ip_address, port):
        """ Connects the pd_bit_sub_listener to another ZMQ PUB socket for receiving bits.
        """
        # Connect
        self.pd_bit_sub_listener.connect("tcp://" + ip_address + ":" + port)
        
    def removePubSocket(self, address):
        """ Removes the ZMQ PUB from the pd_bit_sub_listener.
        """
        # Disconnect
        self.pd_bit_sub_listener.disconnect("tcp://" + address)         
        
    def loadConfiguration(self):
        """ Loads a configuration YAML file with all the FISSURE user settings.
        """
        # Load Settings from YAML File
        filename = os.path.dirname(os.path.realpath(__file__)) + "/YAML/fissure_config.yaml"
        yaml_config_file = open(filename)
        self.settings_dictionary = yaml.load(yaml_config_file, yaml.FullLoader)
        yaml_config_file.close()   
        
            
    #################  Protocol Discovery Functions  ###################
    
    def updateFISSURE_Configuration(self):
        """ Reload fissure_config.yaml after changes.
        """
        # Update FGE Dictionary
        self.settings_dictionary = self.loadConfiguration()
    
    def startPD(self):
        """ This function starts protocol discovery.
        """
        # Start Processing Bits
        self.gr_processing = threading.Event()
        self.gr_srv = threading.Thread(target = self.grRcvThread, args=(self.gr_processing, self.pd_bit_sub_listener,));           
        self.gr_srv.setDaemon(True)
        self.gr_srv.start()        

    def stopPD(self):
        """ This function stops the grcRcv thread.
        """
        try:
            self.gr_processing.set()
        except:
            pass    
            
    def grRcvThread(self, stop_event, socket):
         """ Threaded function to update buffer running in background.
             Stop the thread by changing global variable gr_processing to False.
             Change the size of the buffer by setting global variable "max_buffer" to the correct size.
             (Note that zmq buffer appears to be 32kb)
             Flush the buffer by changing global variable "flush_buffer" to True.     
         """
         self.my_output_buffer = ""    
         while(not stop_event.is_set()):      
            try:
                msg = socket.recv(zmq.NOBLOCK)
            except zmq.ZMQError:
                msg = ""        
            if msg:
                if len(msg) > 3:
                    grinput = msg[3:]  # Part of ZMQ header (Command Length, Command)
            else:
                grinput = ""

            self.my_output_buffer += binascii.hexlify(grinput)
            if len(self.my_output_buffer) > self.max_buffer:
                self.my_output_buffer = self.my_output_buffer[(len(self.my_output_buffer) - self.max_buffer):]        
            if self.flush_buffer:     
                self.my_output_buffer = ""
                self.flush_buffer = False     
              
            # Report the Buffer Size to the Dashboard
            if float(self.buffer_size_time) < time.time() - (float(self.settings_dictionary['buffer_size_interval'])):
                self.buffer_size_time = time.time()
                    
                # Send the Message to the Dashboard
                self.pd_pub_server.sendmsg('Status', Identifier = 'PD', MessageName = 'Buffer Size', Parameters = len(self.my_output_buffer)) 
                
            time.sleep(0.5)
            
    def searchLibraryForFlowGraphsCallback(self, soi_data, hardware):
        """ Calls searchLibraryForFlowGraphs() as a threaded callback.
        """     
        # Do Function in a New Threaded Callback
        search_library_for_flow_graphs_thread = ThreadingCallback(self.pd_pub_server,'Set Recommended Flow Graphs', self.searchLibraryForFlowGraphs, soi_data, hardware)        
        search_library_for_flow_graphs_thread.start()
        
    def searchLibraryForFlowGraphs(self, soi_data, hardware):
        """ Look up the SOI to recommend a best-fit demodulation flow graph from the library.
        """     
        # Check Hardware          
        if len(hardware) == 0:
            hardware = None
        
        # Search the Library for SOI
        get_sois = self.searchLibrary(soi_data,"")
        
        # Get All Flow Graphs for Each Protocol
        flow_graph_names = []
        if soi_data[1] == "":
            for s in get_sois:
                flow_graph_names.extend(getDemodulationFlowGraphs(self.pd_library,s[s.keys()[0]]['Protocol'],None,hardware))
        
        # Keep Names with Same Modulation 
        else:
            for s in get_sois:
                flow_graph_names.extend(getDemodulationFlowGraphs(self.pd_library,s[s.keys()[0]]['Protocol'],soi_data[1],hardware))
        
        return list(set(flow_graph_names)) # Only the unique values
        
        # Find Flow Graphs with Same Modulation Type    
        #~ same_modulation_protocol_names = {protocol: getDemodulationFlowGraphs(pd_library,protocol) for protocol,mod in getModulations(pd_library).iteritems() if modulation in mod}      
            
        #~ pd_pub_server.sendmsg('Status', Identifier = 'PD', MessageName='Set Recommended Flow Graphs', Parameters=same_modulation_protocol_names) 

        #~ return same_modulation_protocol_names       
        
    def searchLibrary(self,soi_data, field_data):
        """ Callback to search for the Candidate preamble in Library
            preambles passed in as list, returns pakets and protocols found in
            (returns packet type as key so if found for multiple packets of same protocol,
            we can report to user)
            soi_data = ['center_freq', 'modulation', 'bandwidth', 'continuous', 'start_freq', 'end_freq', 'center_freq+-', 'bandwidth+-', 'start_freq+-', 'end_freq+-']

        """            
        ## Find Matching SOI Data
        return_list = []
        
        # Check if soi_data is Empty
        soi_data_empty = True
        for get_item in soi_data:
            if get_item != "":
                soi_data_empty = False
                break
        
        if soi_data_empty == False:        
            # Get the SOI Data from the Library      
            all_soi = getAllSOIs(self.pd_library)  
            
            # Cycle through each Protocol    
            for protocol,soi_items in all_soi.iteritems():   
                soi_data_item_found = [False, False, False, False, False, False] 
                and_cases = [True, True, True, True, True, True]
                
                # Cycle through each SOI
                for soi_item in soi_items:
                    
                    # Cycle through each SOI Data Element
                    for n in range(0,len(soi_data_item_found)):
                        # Check if the Element is Empty (Don't Search For It)
                        if soi_data[n] == "":
                            soi_data_item_found[n] = False
                            and_cases[n] = False
                        else:
                            # Frequency
                            if n == 0:
                                if (float(soi_data[n])-float(soi_data[6]) <= float(soi_items[soi_item]["Frequency"])) and \
                                (float(soi_data[n])+float(soi_data[6]) >= float(soi_items[soi_item]["Frequency"])):
                                    soi_data_item_found[n] = True
                            # Modulation
                            if n == 1:
                                if soi_data[n].lower() in soi_items[soi_item]["Modulation"].lower():  # Not case-specific
                                    soi_data_item_found[n] = True
                            # Bandwidth
                            if n == 2:
                                if (float(soi_data[n])-float(soi_data[7]) <= float(soi_items[soi_item]["Bandwidth"])) and \
                                (float(soi_data[n])+float(soi_data[7]) >= float(soi_items[soi_item]["Bandwidth"])):
                                    soi_data_item_found[n] = True
                            # Continuous
                            if n == 3:
                                if soi_data[n] == str(soi_items[soi_item]["Continuous"]):
                                    soi_data_item_found[n] = True
                            # Start Frequency
                            if n == 4:
                                if (float(soi_data[n])-float(soi_data[8]) <= float(soi_items[soi_item]["Start Frequency"])) and \
                                (float(soi_data[n])+float(soi_data[8]) >= float(soi_items[soi_item]["Start Frequency"])):
                                    soi_data_item_found[n] = True                                                      
                            # End Frequency
                            if n == 5:
                                if (float(soi_data[n])-float(soi_data[9]) <= float(soi_items[soi_item]["End Frequency"])) and \
                                (float(soi_data[n])+float(soi_data[9]) >= float(soi_items[soi_item]["End Frequency"])):
                                    soi_data_item_found[n] = True 
                      
                    # Save the SOI if there is a Match
                    if and_cases == soi_data_item_found:
                        soi_items[soi_item]['Protocol'] = protocol
                        return_dict = {}
                        return_dict.update({soi_item:soi_items[soi_item]})                                
                        return_list.append(return_dict)   
                                    
                    # Reset
                    soi_data_item_found = [False, False, False, False, False, False] 
                        
        ## Find Matching Field Data
        # Check if Field Data is Empty
        field_data_empty = True
        packet_type_protocol_dict = {} 
        if field_data != "":
            field_data_empty = False
            
            # Get the Defaults from the Library  
            def_dict = {}
            for prots in getProtocols(self.pd_library):
                  for pkts in getPacketTypes(self.pd_library, prots):
                      mydefs = getDefaults(self.pd_library, prots, pkts)        
                      mydefs = ''.join(mydefs).replace(' ','')                
                      if mydefs:                   
                          #~ mydefs = str(hex(int(mydefs,2))[2:-1])  # Convert to Hex  
                          
                          # Update the Complete "Protocol:Packet Type:Default Hex Values" Dictionary
                          if prots in def_dict.keys():
                              def_dict[prots].update({pkts: mydefs})        
                          else:
                              def_dict.update({prots:{pkts: mydefs}})     
                
            # Search for Field Data Instances in the Entire Hex Dictionary of the Packet Types, Returns {Packet Type: Protocol}
            for protocols,vals in def_dict.iteritems():
                for packets,packet_vals in vals.iteritems():
                    if field_data in packet_vals:
                        packet_type_protocol_dict[packets] = {'End Frequency': '', 'Protocol': protocols, 'Modulation': '', 'Notes': '', 'Continuous': '', 'Bandwidth': '', 'Frequency': '', 'Start Frequency': ''}                 
                        
        # field_data Attempted to Search
        if field_data_empty == False:
            return_list.append(packet_type_protocol_dict)
        
        return return_list

    def setWindowParameters(self,win_min, win_max, topx, num_std_dev):
        """ Callback to allow HIPRFISR to change buffer size.
        """
        self.min_size = int(win_min)
        self.max_size = int(win_max)
        self.ranking = int(topx)
        self.num_std = int(num_std_dev)
        
        #~ pd_pub_server.sendmsg('Status', Identifier = 'PD', MessageName='Window Parameters Set', Parameters=[winmin,winmax,topx,num_std_dev])    

    def captureBuffer(self):
        """ Callback to send buffer to HIPRFISR so user can interact with it.
        """
        #set buffer to the one we sent the HIPRFISR
        #add flush_buffer to refresh the buffer we're using    
        if not self.hiprfisr_buffer: 
            self.hiprfisr_buffer = self.my_output_buffer            
        self.pd_pub_server.sendmsg('Status', Identifier = 'PD', MessageName='Return Captured Buffer', Parameters=self.hiprfisr_buffer)
        #~ print "Sending buffer to HIPRFISR/Dashboard"

    def findPreambles(self):
        """ Callback to send the current best estimate of preamble stats to HIPRFISR so user can see preamble candidates in the latest buffer.
        """ 
        # If this is the First Time, Set up HIPRFISR Buffer
        #~ global FindPreamblesThreaded
        if not self.hiprfisr_buffer: 
            self.hiprfisr_buffer = self.my_output_buffer       
        self.FindPreamblesThreaded = ThreadingCallback(self.pd_pub_server,'Found Preambles', self.minStdMaxLenMedPktPreambles, self.hiprfisr_buffer,self.min_size,self.max_size,self.ranking,self.num_std)    
        self.FindPreamblesThreaded.start()
        #~ print "Finding Preambles and Sending to HIPRFISR/Dashboard"
        
    def searchLibraryCallback(self,soi_data, field_data):
        """ Callback to search the library for matching SOI values, field values, and statistics.
        """        
        # Do Function in a New Threaded Callback
        self.FindPreamblesinLibraryThreaded = ThreadingCallback(self.pd_pub_server,'Found Preambles in Library', self.searchLibrary, soi_data, field_data)        
        self.FindPreamblesinLibraryThreaded.start()

    def readBits(self):
        """ Read all the data in the bit listener and handle it accordingly.
        """           
        # PD is Running   
        if (not self.gr_processing.is_set()):
            # had trouble that protocol discovery was starting up before flowgraph was loading
            # giving FGE 0.25 secs to start, then we start threading the preambles
            # this can be adjusted if necessary later, or if running non-locally    
            time.sleep(1)    
            
            # starts threaded callback to return value to HIPRFISR
            if self.finding_preambles:
                if len(self.my_output_buffer) >= self.min_buffer:
                    #~ print "Searching for preambles"                    
                    self.finding_preambles = False            
                    self.findPreambles()
                else:
                    pass
                    #~ print "Filling Buffer..."
            else: 
                try:
                    #~ print "waiting for Preamble return from thread"
                    self.FindPreamblesThreaded.returnval                
                except: # AttributeError:            
                    # Thread Hasn't Returned Yet
                    pass
                else:
                    # Starts Threaded Callback to Search Library with already Searched Return Value (could also do this from HIPRFISR/Dashboard Selected result
                    if self.lib_search:
                        self.lib_search = False
                        self.findPreamblesInLibrary(self.FindPreamblesThreaded.returnval.keys()[0])
                            
    #~ def findPacketLengths(data,preambles):
        #~ """ Finds the packet lengths of the data for each selected preamble???
        #~ """
        #~ packet_lengths = {}
        #~ for preamble in preambles:
            #~ idxs = findAll(data,preamble)
            #~ packet_lengths.update({preamble: Counter(np.diff(idxs))})

    #~ def listensocket():
        #~ """ Not used yet.
        #~ """
        #~ c = zmq.Context()
        #~ s = c.socket(zmq.SUB)
        #~ s.setsockopt(zmq.SUBSCRIBE,'')
        #~ s.connect("tcp://localhost:5555")
        #~ alphabet='01'

    def longestCommonSubstring(self,s1, s2):
        """ Returns the longest common substring between two strings.
        """
        m = [[0] * (1 + len(s2)) for i in xrange(1 + len(s1))]
        longest, x_longest = 0, 0
        for x in xrange(1, 1 + len(s1)):
            for y in xrange(1, 1 + len(s2)):
                if s1[x - 1] == s2[y - 1]:
                    m[x][y] = m[x - 1][y - 1] + 1
                    if m[x][y] > longest:
                        longest = m[x][y]
                        x_longest = x
                else:
                    m[x][y] = 0
        return s1[x_longest - longest: x_longest]
            
    def findCommonSubs(self,data,winmin,winmax,topx):
        """ Searches a sliding window for the most common substrings within.
        """
        frequent_common_subs = {}
        for winlen in range(winmin,winmax+1): 
            frequent_common_subs.update(Counter(data[i:i+winlen] for i in range(len(data)-winlen)).most_common(topx))  
        return frequent_common_subs 
     
    def findAll(self,findin, tofind):
        """ Finds all matching strings in a string?
        """
        return [idxs.start() for idxs in re.finditer(tofind.lower(), findin.lower())]

    def slicingStats(self,preambles,datablob):
        """ Calculates the slicing stats for each preamble.
        """
        slicestats = {}
        idxs = {}
        for preamble in preambles.iterkeys():
            idxs = self.findAll(datablob,preamble)
            mdian = np.median(np.diff(idxs))
            meanie = np.mean(np.diff(idxs))
            stddev = np.std(np.diff(idxs))
            slicestats.update({preamble: (len(preamble),mdian,meanie,stddev,preambles[preamble])})
        return slicestats
         
    def minStdMaxLenMedPktPreambles(self,data,winmin,winmax,topx,num_std_dev):
         """ Find topx most common preambles that are between winmin and winmax 
             that are within num_std standard deviations of the mean length (we assume
             a single type of packet is more common than the others).
         """ 
         # Find Frequent Common Substrings as Initial Guess at Preamble
         fcs = self.findCommonSubs(data,winmin,winmax,topx)  # Return the top values to the Dashboard?         

         # Calculate Number of Packets in Data Blob, Median/Mean Length, Length Variance
         # When Sliced with that Preamble, and Length of Preamble
         slice_medians = self.slicingStats(fcs,data) 
         
         # Filter Preambles that Minimize (within 2) Standard Deviation on Packet Length (i.e. only Looking for one Packet Type)    
         min_std_dev = np.min(zip(*slice_medians.values())[3])
         
         # we could also filter out preambles that don't contain the most common 
         # "letters" of the alphabet over the data blob, but that's for a future task             
         min_std_dev_preambles = {keys: values for keys, values in slice_medians.iteritems() if values[3]<=num_std_dev*min_std_dev}
         
         # Find the Median Number of Slices Across all Preambles
         # (preambles that produce the average number of packets should be a common enough preamble)
         print min_std_dev_preambles.values()
         median_num_slices = np.floor(np.median(zip(*min_std_dev_preambles.values())[4]))    
         
         # Find the Median Packet Length when using those Preambles (we're assuming a single type of packet pops up more than others to give us a bit of something to go on)          
         median_length = np.median(zip(*slice_medians.values())[1])  # Not used?
         
         # Filter out Preambles that don't give us the Median Number of Slices (we're allowing for multiple preambles to pass through)
         candidate_preambles = {keys: values for keys, values in slice_medians.iteritems() if values[4]==median_num_slices}  # Not used?
         
         # Pick the Longest Preambles of those that are Left (the longest common substring that minimizes the standard deviation and produces packets of the median length)
         max_length_min_std_dev = np.max(zip(*min_std_dev_preambles.values())[0])
         min_std_dev_max_length_preambles = {keys: values for keys, values in min_std_dev_preambles.iteritems() if values[0]==max_length_min_std_dev}     
         
         #~ print "FCS"
         #~ print fcs
         #~ print "SLICE MEDIANS"
         #~ print slice_medians
         #~ print "MIN STD DEV"
         #~ print min_std_dev
         #~ print "MIN STD DEV PREAMBLES"
         #~ print min_std_dev_preambles
         #~ print "MEDIAN LENGTH"
         #~ print median_length
         #~ print "CANDIDATE PREAMBLES"
         #~ print candidate_preambles
         #~ print "MAX LENGTH MIN STD DEV"
         #~ print max_length_min_std_dev
         #~ print "MIN STD DEV MAX LENGTH PREAMBLES"
         #~ print min_std_dev_max_length_preambles
         
         return [slice_medians, candidate_preambles, min_std_dev_max_length_preambles]
     
    #~ def simpleChanges(data,alphabet):
        #~ """ Not used yet.
        #~ """
        #~ splits     = [(data[:i], data[i:]) for i in range(len(data) + 1)]
        #~ removals    = [a + b[1:] for a, b in splits if b]
        #~ transpositions = [a + b[1] + b[0] + b[2:] for a, b in splits if len(b)>1]
        #~ replaces   = [a + c + b[1:] for a, b in splits for c in alphabet if b]
        #~ inserts    = [a + c + b     for a, b in splits for c in alphabet]
        #~ return set(removals + transpositions + replaces + inserts)
        
    def sliceByPreamble(self,preamble, first_n, estimated_length):
        """ This slices the buffer by a preamble and returns the lengths, the length counts, and the top N packets for each length.
        """    
        # Convert Bits to Nibbles
        estimated_length = int(int(estimated_length)/4)
        
        # Take a Snapshot of the Buffer
        current_buffer = self.my_output_buffer
        
        # Get the Preamble Locations in the Data
        idxs = self.findAll(current_buffer,preamble)
        
        if len(idxs) > 0:
            # Get the Lengths and Occurrences
            idxs.append(len(current_buffer)-1)  # Don't skip last match on the upcoming 'np.diff(idxs)'
            if estimated_length == 0:
                packet_lengths = Counter(np.diff(idxs))  # Or leave a Counter object and find the most common when populating the table
                packet_lengths = packet_lengths.most_common()    
            else:
                packet_lengths = Counter([estimated_length]*(len(idxs)-1))
                packet_lengths = packet_lengths.most_common()    
            
            # Get First N Packets for each Length
            packet_dict = {}
            for n in range(0,len(packet_lengths)):
                packet_dict[packet_lengths[n][0]] = []
                
            # Guess the Estimated Length for Each Message
            buffer_index = idxs[0]   
            if estimated_length == 0:            
                for p_length in np.diff(idxs):
                    if len(packet_dict[p_length]) < int(first_n):
                        packet_dict[p_length].append(current_buffer[buffer_index:buffer_index+p_length])
                    buffer_index += p_length
                    
            # Use the Provided Message Length
            else:
                for i in range(0,packet_lengths[0][1]):
                    if i < int(first_n):
                        packet_dict[int(estimated_length)].append(current_buffer[idxs[i]:idxs[i]+estimated_length])
                    
            # Send the Message to the Dashboard
            self.pd_pub_server.sendmsg('Status', Identifier = 'PD', MessageName = 'Slice By Preamble Return', Parameters = [packet_lengths, packet_dict]) 
        
        # No Matches Found
        else:
            # Send the Message to the Dashboard
            self.pd_pub_server.sendmsg('Status', Identifier = 'PD', MessageName = 'Slice By Preamble Return', Parameters = [[], {}])
        
    def setBufferSize(self,min_buffer_size, max_buffer_size):
        """ Sets the minimum and maximum sizes for the circular buffer.
        """
        self.min_buffer = int(min_buffer_size)
        self.max_buffer = int(max_buffer_size)
        
    def clearPD_Buffer(self):
        """ Clears the contents of the Protocol Discovery buffer.
        """
        # Cancel the Thread
        self.gr_processing.set()
        
        # Close the Socket
        pd_bits_port = self.settings_dictionary['pd_bits_port']
        pd_default_ip_address = "127.0.0.1"
        self.pd_bit_sub_listener.disconnect("tcp://" + self.bit_ip_address + ":" + str(pd_bits_port))  # 'localhost' causes issues with FGE Flow Graphs for some reason
        
        # Flush the Buffer
        self.flush_buffer = True
        
        # Restart the Socket
        try:           
            self.pd_bit_sub_listener.connect("tcp://" + self.bit_ip_address + ":" + str(pd_bits_port))  # 'localhost' causes issues with FGE Flow Graphs for some reason            
            self.pd_bit_sub_listener.setsockopt_string(zmq.SUBSCRIBE,u'')
            
            # Set up Thread to Fill Read Buffer up to max_buffer
            self.gr_processing = threading.Event()
            self.gr_srv = threading.Thread(target = self.grRcvThread, args=(self.gr_processing, self.pd_bit_sub_listener,));           
            self.gr_srv.setDaemon(True)
            self.gr_srv.start()                 
         
        except KeyError, e:
            print "Unable to connect PD SUB to FGE PUB"  
                
    def findEntropyCallback(self, message_length, preamble):
        """ Calls the findEntropy() function in a new thread and returns a message on the pub socket when completed.
        """
        # Do Function in a New Threaded Callback
        self.FindEntropyThreaded = ThreadingCallback(self.pd_pub_server,'Entropy Return', self.findEntropy, message_length, preamble)        
        self.FindEntropyThreaded.start()
            
    def findEntropy(self, message_length, preamble):
        """ Finds the entropy for the bit positions of a fixed length message.
        """        
        # Take a Snapshot of the Buffer
        current_buffer = self.my_output_buffer
        
        # Get the Preamble Locations in the Data
        idxs = self.findAll(current_buffer,preamble)
        
        # Get Packets of Length 'message_length'
        packet_list = []            
        idxs_diff = np.diff(idxs)
        for n in range(0,len(idxs_diff)):
            if idxs_diff[n] >= int(message_length/4):  # Message Length is in Bits, Divide by Four Converts to Hex
                packet_list.append(current_buffer[idxs[n]:idxs[n]+message_length/4])
        
        # Convert Hex to Binary
        binary_packet_list = []
        # ~ print len(packet_list)
        for packet in packet_list:
            hex_len = len(packet)
            bin_str = bin(int(packet, 16))[2:].zfill(hex_len*4)
            binary_packet_list.append(bin_str)
            
        # Convert Packets into Lists of Bit Positions
        # ~ print len(binary_packet_list[0])
        bit_pos = []
        for i in range (0, len(binary_packet_list[0])):
            bit_pos.append([])
        for i in binary_packet_list:
            for j in range (0, len(i)):
                bit_pos[j].append(i[j])
                
        # Find Entropy for Bit Positions
        ents = []
        for bit in range(0, len(bit_pos)):
            ent = self.calculateEntropy(bit_pos[bit])
            ents.append(ent)
        
        return ents       
                
    def calculateEntropy(self,vals):
        """ Calculates Entropy for a list of values.
        """
        # Calculate Entropy
        num_vals = len(vals)
        counts = np.bincount(vals)
        if len(counts) == 1:
            counts = np.array([counts[0], 0])
        if len(counts) != 2:
            pass
            #~ raise ValueError('Error calculating entropy. Unexpected number of counts.')
        freqs = counts / float(num_vals)
        ent = 0.0
        for val in freqs:
            if val != 0:
                ent += val * np.log2(val)
        if ent < 0:
            ent = - ent

        # Round Entropy
        ent = round(ent,2)
    
        return ent
             
    
if __name__=="__main__":
    # Create Protocol Discovery Object
    pd = ProtocolDiscovery()
    


