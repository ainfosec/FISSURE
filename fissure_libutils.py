import yaml
import copy

#convenience function to keep from having to re-write the library schema

def getFields(library, protocol, packet_type):
    """
    """
    try: 
        fields = sorted(library['Protocols'][protocol]['Packet Types'][packet_type]['Fields'], key=lambda x: library['Protocols'][
                            protocol]['Packet Types'][packet_type]['Fields'][x]['Sort Order'])        
    except KeyError,e:
        fields = []
    return fields

def newField(fieldname="",defaultvalue="",length=0,sortorder=1, iscrc="False",crcrange=""):
    """
    """
    if not fieldname:
        fieldname = 'New Field'
    if not length:
        length = len(defaultvalue)
        
    if iscrc == "True":
        iscrc = True
    else:
        iscrc = False
    
    if crcrange == "":
        new_field_subdict = {fieldname: {"Default Value": defaultvalue, "Length": int(length), 'Sort Order': int(sortorder), 'Is CRC':bool(iscrc)}}
    else:
        new_field_subdict = {fieldname: {"Default Value": defaultvalue, "Length": int(length), 'Sort Order': int(sortorder), 'Is CRC':bool(iscrc), 'CRC Range':str(crcrange)}}
    return new_field_subdict     

def newPacket(pkttype="", fields=newField()):
    """
    """
    if not pkttype:
        pkttype = "New Packet"
    new_packet_type_dict = {pkttype: {'Fields': fields, 'Dissector':{'Filename': None, 'Port': None}, 'Sort Order':-1}}
    return new_packet_type_dict
    
def getPacketTypes(library, protocol):
    """
    """
    try: 
        packettypes = sorted(library['Protocols'][protocol]['Packet Types'], key=lambda x: library['Protocols'][
                                        protocol]['Packet Types'][x]['Sort Order'])
    except KeyError,e:
        packettypes = []
    return packettypes

def getFieldProperties(library, protocol, packet_type, field):
    """
    """
    try: 
        field_properties = library['Protocols'][protocol]['Packet Types'][packet_type]['Fields'][field]        
    except KeyError,e:
        field_properties = []
    return field_properties
    
def getDefaults(library, protocol, packet_type):
    """
    """
    try:
        fields = sorted(library['Protocols'][protocol]['Packet Types'][packet_type]['Fields'], key=lambda x: library['Protocols'][
                            protocol]['Packet Types'][packet_type]['Fields'][x]['Sort Order'])        
        default_field_data = [library['Protocols'][protocol]['Packet Types'][
                            packet_type]['Fields'][field]['Default Value'] for field in fields]        
    except KeyError, e:
        fields = []
        default_field_data = []
    return default_field_data
    
def newProtocol(protocolname="", attacks={},demodflowgraph='',modtype="", \
                 pkttypes = newPacket()):
    """ Adds an empty protocol to a library.
    """  
    
    new_protocol_dict = {protocolname: {'Null Placeholder':None}}
        
    return new_protocol_dict                                        

def getProtocols(library):
    """
    """
    try: 
        protocols = [protocols for protocols in library['Protocols'].iterkeys()]
    except KeyError,e:
        protocols = []
    return protocols
    
def getProtocol(library, protocol_name):
    """
    """
    try: 
        protocol = library['Protocols'][protocol_name]
    except KeyError,e:
        protocol = []
    return protocol
    
def getDemodulationFlowGraphsModulation(library, protocol=None):
    """ Returns the modulation types for a protocol's demodulation flow graphs.
    """
    get_modulation = []
    if protocol:
        try:
            get_modulation.extend(library['Protocols'][protocol]['Demodulation Flow Graphs'])                        
        except KeyError,e:
            pass
    else:
        for protocol in getProtocols(library):         
            try:
                get_modulation.extend(library['Protocols'][protocol]['Demodulation Flow Graphs']) 
            except KeyError,e:
                pass
                
    return list(set(get_modulation))      
    
def findValueByKey(d, tag):
    for k, v in d.items():
        if isinstance(v, dict):
            for i in findValueByKey(v, tag):
                yield i
        elif k == tag:
            yield v   
    
def getDemodulationFlowGraphsSnifferType(library, flow_graph):
    """ Returns the sniffer types for a protocol's demodulation flow graphs.
    """
    get_sniffer_type = ""
    
    for x in findValueByKey(library, flow_graph):
        get_sniffer_type = x[0]
        break
                        
    return get_sniffer_type          
    
def getDemodulationFlowGraphsHardware(library, protocol=None, modulation=None):
    """ Returns the hardware types for demodulation flow graphs of a library.
    """
    get_hardware = []
    if protocol:
        try:
            if modulation:
                    library['Protocols'][protocol]['Demodulation Flow Graphs'][modulation]
                    get_hardware.extend(library['Protocols'][protocol]['Demodulation Flow Graphs'][modulation])
            else:
                for m in library['Protocols'][protocol]['Demodulation Flow Graphs']:
                    get_hardware.extend(library['Protocols'][protocol]['Demodulation Flow Graphs'][m])                        
        except KeyError,e:
            pass
    else:
        for protocol in getProtocols(library):         
            try:
                if modulation:
                    get_hardware.extend(library['Protocols'][protocol]['Demodulation Flow Graphs'][modulation]) 
                else:
                    for m in library['Protocols'][protocol]['Demodulation Flow Graphs']:
                        get_hardware.extend(library['Protocols'][protocol]['Demodulation Flow Graphs'][m]) 
            except KeyError,e:
                pass
                
    return list(set(get_hardware))  
    

def getDemodulationFlowGraphs(library, protocol=None, modulation=None, hardware=None):    
    """
    """
    demod_flowgraphs = []
    if protocol:
        try:
            if modulation:
                if hardware:
                    try:
                        demod_flowgraphs.extend(library['Protocols'][protocol]['Demodulation Flow Graphs'][modulation][hardware])
                    except:
                        pass
                else:
                    for h in library['Protocols'][protocol]['Demodulation Flow Graphs'][modulation]:
                        demod_flowgraphs.extend(library['Protocols'][protocol]['Demodulation Flow Graphs'][modulation][h])
            else:
                for m in library['Protocols'][protocol]['Demodulation Flow Graphs']:
                    if hardware:
                        try:
                            demod_flowgraphs.extend(library['Protocols'][protocol]['Demodulation Flow Graphs'][m][hardware])
                        except:
                            pass
                    else:
                        for h in library['Protocols'][protocol]['Demodulation Flow Graphs'][m]:
                            demod_flowgraphs.extend(library['Protocols'][protocol]['Demodulation Flow Graphs'][m][h])                        
        except KeyError,e:
            #print "Error: No Demodulation Flowgraph Defined ",e, "for protocol", protocol
            pass
    else:
        for protocol in getProtocols(library):         
            try:
                if modulation:
                    if hardware:
                        try:
                            demod_flowgraphs.extend(library['Protocols'][protocol]['Demodulation Flow Graphs'][modulation][hardware])
                        except:
                            pass
                    else:
                        for h in library['Protocols'][protocol]['Demodulation Flow Graphs'][modulation]:
                            demod_flowgraphs.extend(library['Protocols'][protocol]['Demodulation Flow Graphs'][modulation][h])
                else:
                    for m in library['Protocols'][protocol]['Demodulation Flow Graphs']:
                        if hardware:
                            try:
                                demod_flowgraphs.extend(library['Protocols'][protocol]['Demodulation Flow Graphs'][m][hardware])
                            except:
                                pass
                        else:
                            for h in library['Protocols'][protocol]['Demodulation Flow Graphs'][m]:
                                demod_flowgraphs.extend(library['Protocols'][protocol]['Demodulation Flow Graphs'][m][h])
            except KeyError,e:
                #print "Error: No Demodulation Flowgraph Defined ",e, "for protocol", protocol
                pass
                
    return list(set(demod_flowgraphs))  # Only the Unique Values
    
def newSOI(frequency = 0, modulation  = '', bandwidth = 0, continuous = "False", start_frequency = 0, end_frequency = 0, notes = '', subtype = ''):
    """
    """
    if continuous == "True":
        continuous = True
    else:
        continuous = False
        
    new_soi_dict = {str(subtype): {'Frequency': float(frequency), \
                                 'Modulation': str(modulation), \
                                 'Bandwidth': float(bandwidth), \
                                 'Continuous': bool(continuous), \
                                 'Start Frequency': float(start_frequency), \
                                 'End Frequency': float(end_frequency), \
                                 'Notes': str(notes)}}
    return new_soi_dict
    
def newStatistics(datarates = [],packetlengths = []):
    """
    """
    new_statistics_dict = {'Statistics': {'Data Rates': datarates, \
                                          'Median Packet Lengths': packetlengths}}
    return new_statistics_dict
                   
def getAllSOIs(library):
    """
    """
    sois = {}
    for protocol in getProtocols(library):         
        try:
            sois.update({protocol: library['Protocols'][protocol]['SOI Data']})
        except KeyError,e:
            pass
            #print "Error: No Key ",e, "for protocol", protocol

    return sois
    
def getSOIs(library, protocol):
    """ Returns the SOIs of a protocol.
    """
    sois = {}
    try:
        sois = library['Protocols'][protocol]['SOI Data']     
    except KeyError,e:
        pass
        #print "Error: No Key ",e, "for protocol", protocol
    
    return sois
    
def getAttacks(library, protocol):
    """ Returns the attacks for a protocol.
    """
    attacks = {}
    updated_attacks = []
    try:
        attacks = library['Protocols'][protocol]['Attacks']   
        exclude_list = ["Single-Stage", "Denial of Service", "Jamming", "Spoofing", "Sniffing/Snooping", "Probe Attacks", "Installation of Malware", "Misuse of Resources", "File", "Multi-Stage", "New Multi-Stage", "Fuzzing", "Variables"]
        for n in attacks:
            if n not in exclude_list:
                updated_attacks.append(n)
    except KeyError,e:
        pass
        #print "Error: No Key ",e, "for protocol", protocol
    
    return updated_attacks    
    
def getStatistics(library, protocol):
    """ Returns the statistical categories for a protocol.
    """
    statistics = {}
    try:
        statistics = library['Protocols'][protocol]['Statistics']     
    except KeyError,e:
        pass
        #print "Error: No Key ",e, "for protocol", protocol
    
    return statistics    
    
def getStatisticValues(library, protocol, statistic):
    """ Returns the values for a statistic.
    """
    values = []
    try:
        if library['Protocols'][protocol]['Statistics'][statistic] != "None":
            values = library['Protocols'][protocol]['Statistics'][statistic]
    except KeyError,e:
        pass
        #print "Error: No Key ",e, "for protocol", protocol
    
    return values      

def getModulations(library, protocol):
    """
    """
    modulations = []
    try:
        modulations = library['Protocols'][protocol]['Modulation Types']
    except KeyError,e:
        pass
        #print "Error: No Key ",e, "for protocol", protocol
        
    return modulations
    
def getDissector(library, protocol, packet_type):
    """ Returns the name and port of a dissector for a particular packet type.
    """
    dissector = library['Protocols'][protocol]['Packet Types'][packet_type]['Dissector']
    
    return dissector
    
def getNextDissectorPort(library):
    """ Returns an unassigned dissector UDP port.
    """
    max_dissector_port = -1
    for protocol in getProtocols(library):         
        for packet_type in getPacketTypes(library, protocol):
            try:
                get_port = int(library['Protocols'][protocol]['Packet Types'][packet_type]['Dissector']['Port'])
                if get_port > max_dissector_port:
                    max_dissector_port = get_port + 1
            except:
                pass
                
    return max_dissector_port
    
    
def addPacketType(library, protocol, packet_type):
    """
    """
    try:
        library['Protocols'][protocol]['Packet Types'].update(packet_type)
    except KeyError,e:
        library['Protocols'][protocol].update({'Packet Types':packet_type})
        
def addDissector(library, protocol, packet_type, dissector_filename, dissector_port):
    """ Replaces the dissector filename and port for a packet type. There should only be one dissector per packet type.
    """
    try:
        dissector_dict = {'Filename':dissector_filename, 'Port':dissector_port}
        library['Protocols'][protocol]['Packet Types'][packet_type]['Dissector'].update(dissector_dict)
    except KeyError,e:
        library['Protocols'][protocol]['Packet Types'][packet_type].update({'Dissector':dissector_dict})
 
def addProtocol(library, protocol=newProtocol()):
    """
    """
    library['Protocols'].update(protocol)
    
def addModulation(library, protocol, modulation):
    """ Adds a new modulation type to a library.
    """
    # Check if Template Exists
    try: 
        library['Protocols'][protocol]['Modulation Types'].append(modulation)
    except KeyError,e:
        library['Protocols'][protocol].update({'Modulation Types':[modulation]})   
        
    ## Add Initial Template
    #empty = ""
    #try:
        #empty = library['Protocols'][protocol]['Attack Categories']['Single-Stage']          
    #except KeyError:
        ## Default Attack Categories    
        #attack_dict = {'Single-Stage':{modulation:{'Hardware':{'USRP X310':'None'}}}}
        #attack_dict['Single-Stage'][modulation]['Hardware'].update({'USRP XB210':'None'})
        #attack_dict['Single-Stage'][modulation]['Hardware'].update({'HackRF':'None'})
        #attack_dict['Single-Stage'][modulation]['Hardware'].update({'RTL2832U':'None'})
        #attack_dict['Single-Stage'][modulation]['Hardware'].update({'802.11x Adapter':'None'})
        
        #attack_dict.update({'Multi-Stage':{modulation:{'Hardware':{'USRP X310':'None'}}}})
        #attack_dict['Multi-Stage'][modulation]['Hardware'].update({'USRP XB210':'None'})
        #attack_dict['Multi-Stage'][modulation]['Hardware'].update({'HackRF':'None'})
        #attack_dict['Multi-Stage'][modulation]['Hardware'].update({'RTL2832U':'None'})
        #attack_dict['Multi-Stage'][modulation]['Hardware'].update({'802.11x Adapter':'None'})
        
        #attack_dict.update({'New Multi-Stage':{modulation:{'Hardware':{'USRP X310':'None'}}}})
        #attack_dict['New Multi-Stage'][modulation]['Hardware'].update({'USRP XB210':'None'})
        #attack_dict['New Multi-Stage'][modulation]['Hardware'].update({'HackRF':'None'})
        #attack_dict['New Multi-Stage'][modulation]['Hardware'].update({'RTL2832U':'None'})
        #attack_dict['New Multi-Stage'][modulation]['Hardware'].update({'802.11x Adapter':'None'})
                
        #attack_dict.update({'Fuzzing':{modulation:{'Hardware':{'USRP X310':'None'}}}})
        #attack_dict['Fuzzing'][modulation]['Hardware'].update({'USRP XB210':'None'})
        #attack_dict['Fuzzing'][modulation]['Hardware'].update({'HackRF':'None'})
        #attack_dict['Fuzzing'][modulation]['Hardware'].update({'RTL2832U':'None'})
        #attack_dict['Fuzzing'][modulation]['Hardware'].update({'802.11x Adapter':'None'})    
        
        #attack_dict.update({'Variables':{modulation:{'Hardware':{'USRP X310':'None'}}}})
        #attack_dict['Variables'][modulation]['Hardware'].update({'USRP XB210':'None'})
        #attack_dict['Variables'][modulation]['Hardware'].update({'HackRF':'None'})
        #attack_dict['Variables'][modulation]['Hardware'].update({'RTL2832U':'None'})
        #attack_dict['Variables'][modulation]['Hardware'].update({'802.11x Adapter':'None'}) 
    
        #library['Protocols'][protocol].update({'Attack Categories':attack_dict})
        
    ## Do Other Attempts
    #if len(empty) > 0:
        #library['Protocols'][protocol]['Attacks']['Single-Stage'].update({modulation:{'Hardware':{'USRP X310':'None'}}})
        #library['Protocols'][protocol]['Attacks']['Single-Stage'][modulation]['Hardware'].update({'USRP XB210':'None'})
        #library['Protocols'][protocol]['Attacks']['Single-Stage'][modulation]['Hardware'].update({'HackRF':'None'})
        #library['Protocols'][protocol]['Attacks']['Single-Stage'][modulation]['Hardware'].update({'RTL2832U':'None'})
        #library['Protocols'][protocol]['Attacks']['Single-Stage'][modulation]['Hardware'].update({'802.11x Adapter':'None'})
        
        #library['Protocols'][protocol]['Attacks']['Multi-Stage'].update({modulation:{'Hardware':{'USRP X310':'None'}}})
        #library['Protocols'][protocol]['Attacks']['Multi-Stage'][modulation]['Hardware'].update({'USRP XB210':'None'})
        #library['Protocols'][protocol]['Attacks']['Multi-Stage'][modulation]['Hardware'].update({'HackRF':'None'})
        #library['Protocols'][protocol]['Attacks']['Multi-Stage'][modulation]['Hardware'].update({'RTL2832U':'None'})
        #library['Protocols'][protocol]['Attacks']['Multi-Stage'][modulation]['Hardware'].update({'802.11x Adapter':'None'})        
        
        #library['Protocols'][protocol]['Attacks']['New Multi-Stage'].update({modulation:{'Hardware':{'USRP X310':'None'}}})
        #library['Protocols'][protocol]['Attacks']['New Multi-Stage'][modulation]['Hardware'].update({'USRP XB210':'None'})
        #library['Protocols'][protocol]['Attacks']['New Multi-Stage'][modulation]['Hardware'].update({'HackRF':'None'})
        #library['Protocols'][protocol]['Attacks']['New Multi-Stage'][modulation]['Hardware'].update({'RTL2832U':'None'})
        #library['Protocols'][protocol]['Attacks']['New Multi-Stage'][modulation]['Hardware'].update({'802.11x Adapter':'None'})        
     
        #library['Protocols'][protocol]['Attacks']['Fuzzing'].update({modulation:{'Hardware':{'USRP X310':'None'}}})
        #library['Protocols'][protocol]['Attacks']['Fuzzing'][modulation]['Hardware'].update({'USRP XB210':'None'})
        #library['Protocols'][protocol]['Attacks']['Fuzzing'][modulation]['Hardware'].update({'HackRF':'None'})
        #library['Protocols'][protocol]['Attacks']['Fuzzing'][modulation]['Hardware'].update({'RTL2832U':'None'})
        #library['Protocols'][protocol]['Attacks']['Fuzzing'][modulation]['Hardware'].update({'802.11x Adapter':'None'})        
     
        #library['Protocols'][protocol]['Attacks']['Variables'].update({modulation:{'Hardware':{'USRP X310':'None'}}})
        #library['Protocols'][protocol]['Attacks']['Variables'][modulation]['Hardware'].update({'USRP XB210':'None'})
        #library['Protocols'][protocol]['Attacks']['Variables'][modulation]['Hardware'].update({'HackRF':'None'})
        #library['Protocols'][protocol]['Attacks']['Variables'][modulation]['Hardware'].update({'RTL2832U':'None'})
        #library['Protocols'][protocol]['Attacks']['Variables'][modulation]['Hardware'].update({'802.11x Adapter':'None'})        
               
def addAttack(library, protocol, attack):
    """ Adds a new attack to a library.
    """    
    attack_dict = {attack[0]:{attack[1]:{attack[2]:{attack[3]:{attack[4]:attack[5]}}}}}
    file_type = attack[6]
    tree_parent = attack[7]
    
    # Check if Attack, Modulation, Hardware Exists
    attacks_key_exists = []
    attack_exists = []
    modulation_exists = []
    hardware_exists = []
    try:
        # Check if 'Attacks' Key Exists
        library['Protocols'][protocol]['Attacks']
        attacks_key_exists = [1]
        
        # Check if Attack Exists        
        library['Protocols'][protocol]['Attacks'][attack[0]]
        attack_exists = [1]
        
        # Check if Modulation Type Exists
        library['Protocols'][protocol]['Attacks'][attack[0]][attack[1]]
        modulation_exists = [1]
        
        # Check if Hardware Exists
        library['Protocols'][protocol]['Attacks'][attack[0]][attack[1]]['Hardware'][attack[3]]
        hardware_exists = [1]
    except KeyError,e:
        pass    
    
    # Add Attack and 'Attack' Key if not Already Present
    if len(attacks_key_exists) > 0:
        if len(attack_exists) > 0:
            if len(modulation_exists) > 0:
                if len(hardware_exists) > 0:
                    pass  # Should not get here: Error
                else:
                    library['Protocols'][protocol]['Attacks'][attack[0]][attack[1]]['Hardware'].update(attack_dict[attack[0]][attack[1]][attack[2]])
            else:
                library['Protocols'][protocol]['Attacks'][attack[0]].update(attack_dict[attack[0]])
        else:
            library['Protocols'][protocol]['Attacks'].update(attack_dict)
    else:
        library['Protocols'][protocol].update({'Attacks':attack_dict}) 
        
    # Add Attack to the Attacks Section (Whole Attack List) of the Library
    attack_list = copy.deepcopy(library["Attacks"][file_type + " Attacks"])
    for attack_item in attack_list:
        if tree_parent == attack_item.split(",")[0]:
            index_value = library["Attacks"][file_type + " Attacks"].index(attack_item) + 1
            level = int(attack_item.split(",")[1]) + 1
            new_attack = attack_dict.keys()[0] + "," + str(level)
            if new_attack not in library["Attacks"][file_type + " Attacks"]:
                library["Attacks"][file_type + " Attacks"].insert(index_value,new_attack)   
    
def addSOI(library, protocol, soi):
    """ Adds an SOI to a library.
    """
    # Renumerate Existing SOIs
    existing_sois = getSOIs(library,protocol)
    # temp_soi_dict = {}
    # for s in existing_sois:
        # new_key = "SOI " + str(len(temp_soi_dict) + 1)
        # temp_soi_dict[new_key] = existing_sois[s]

    # New SOI
    existing_sois[soi.keys()[0]] = soi.values()[0]
        
    # Add SOI
    try:
        check_key = library['Protocols'][protocol]['SOI Data']
    except KeyError:
        check_key = None
            
    if check_key == None:
        library['Protocols'][protocol].update({'SOI Data':existing_sois}) 
    else:
        library['Protocols'][protocol]['SOI Data'].update(existing_sois) 
        
def removeSOI(library, protocol, soi):
    """ Removes an SOI from a library.
    """
    # Remove SOI from a Copy
    existing_sois = getSOIs(library,protocol)
    existing_sois.pop(soi)
  
    # # Renumerate Existing SOIs
    # temp_soi_dict = {}
    # for s in existing_sois:
        # new_key = "SOI " + str(len(temp_soi_dict) + 1)
        # temp_soi_dict[new_key] = existing_sois[s]  

    # Update the Library
    library['Protocols'][protocol]['SOI Data'] = existing_sois
    if len(existing_sois) == 0:
        del library['Protocols'][protocol]['SOI Data']   
        
def removePacketType(library, protocol, packet_type):
    """ Removes packet type from a library.
    """    
    # Update the Library
    del library['Protocols'][protocol]['Packet Types'][packet_type]

    if len(library['Protocols'][protocol]['Packet Types']) == 0:
        del library['Protocols'][protocol]['Packet Types']  
        
def removeDemodulationFlowGraph(library, protocol, modulation_type, hardware, demodulation_fg):
    """ Removes demodulation flow graph from a library.
    """
    # Update the Library
    for n in range(0,len(library['Protocols'][protocol]['Demodulation Flow Graphs'][modulation_type][hardware])):
        if demodulation_fg == library['Protocols'][protocol]['Demodulation Flow Graphs'][modulation_type][hardware][n]:
            del library['Protocols'][protocol]['Demodulation Flow Graphs'][modulation_type][hardware][n]
            break

    if len(library['Protocols'][protocol]['Demodulation Flow Graphs'][modulation_type][hardware]) == 0:
        del library['Protocols'][protocol]['Demodulation Flow Graphs'][modulation_type][hardware]   

    if len(library['Protocols'][protocol]['Demodulation Flow Graphs'][modulation_type]) == 0:
        del library['Protocols'][protocol]['Demodulation Flow Graphs'][modulation_type]
        
    if len(library['Protocols'][protocol]['Demodulation Flow Graphs']) == 0:
        del library['Protocols'][protocol]['Demodulation Flow Graphs']    
        
def removeModulationType(library, protocol, modulation_type):
    """ Removes modulation type from a library.
    """                
    # Update the Library    
    for n in range(0,len(library['Protocols'][protocol]['Modulation Types'])):
        if library['Protocols'][protocol]['Modulation Types'][n] == modulation_type:
            del library['Protocols'][protocol]['Modulation Types'][n]

    if len(library['Protocols'][protocol]['Modulation Types']) == 0:
        del library['Protocols'][protocol]['Modulation Types']  
        
    # Delete Attacks from Library
    try:
        attack_dict = copy.deepcopy(library['Protocols'][protocol]['Attacks'])
        for n in attack_dict:
            if modulation_type in attack_dict[n].keys():
                del library['Protocols'][protocol]['Attacks'][n][modulation_type]
                
                if len(library['Protocols'][protocol]['Attacks'][n]) == 0:
                    del library['Protocols'][protocol]['Attacks'][n]
                    
                if len(library['Protocols'][protocol]['Attacks']) == 0:
                    del library['Protocols'][protocol]['Attacks']
    except:
        # To Avoid ['Attacks'] Key Errors
        pass
    
    
    
def addDemodulationFlowGraph(library, protocol, demodulation_type, flow_graph, hardware_type, sniffer_type):
    """ Adds to the list of demodulation flow graphs for a protocol/modulation combination.
    """        
    # Add Modulation Type if not Already Present
    try:
        check_key = library['Protocols'][protocol]['Demodulation Flow Graphs']  
    except KeyError:
        check_key = None
    try:
        library['Protocols'][protocol]['Demodulation Flow Graphs'][demodulation_type][hardware_type][flow_graph].append(sniffer_type)  
    except KeyError:
        if check_key == None:
            library['Protocols'][protocol].update({'Demodulation Flow Graphs':{demodulation_type:{hardware_type:{flow_graph:[sniffer_type]}}}}) 
        else:
            library['Protocols'][protocol]['Demodulation Flow Graphs'][demodulation_type].update({hardware_type:{flow_graph:[sniffer_type]}}) 
            

###################################
# These were copied over, check these two functions.
def SOI_AutoSelect( list1, SOI_priorities, SOI_filters ):	
	""" Sort the SOI_list using specified criteria and choose the best SOI to examine.
		"priority" is a list specifying which list elements in the SOI_list will be sorted by.
		priority = (2, 0, 1) will produce a list that is sorted by element2, then element0, and then element1
		"must_contain" is a list containing elements that narrows the SOI list further by checking for matches after the SOI list is sorted by priority
	""" 
	
	#print 'Unsorted list: {}' .format(list1)	
	
	# Sort the list by element priority
	descending = False
	for x in reversed(range(0,len(SOI_priorities))): 
		if SOI_filters[x] == "Highest":
			list1 = sorted(list1, key=lambda list1: float(list1[SOI_priorities[x]]), reverse=True)
			
		elif SOI_filters[x] == "Lowest":
			list1 = sorted(list1, key=lambda list1: float(list1[SOI_priorities[x]]), reverse=False)
			
		elif SOI_filters[x] == "Nearest to": 
			# Take Absolute Value of Value Differences and then Sort
			new_list_matching = []
			abs_value_list = []
			
			# Absolute Value
			for soi in range(0,len(list1)):
				abs_value_list.append(abs(float(SOI_parameters[x]) - float(list1[soi][SOI_priorities[x]])))
					
			# Sort from Absolute Value
			sorted_index = sorted(range(len(abs_value_list)),key=lambda x:abs_value_list[x])		
			for index in range(0,len(sorted_index)):
				new_list_matching.append(list1[sorted_index[index]])
			list1 = new_list_matching
			
		elif SOI_filters[x] == "Greater than": 
			# Keep Things that Fit Criteria
			new_list_matching = []
			for soi in range(0,len(list1)):
				if float(list1[soi][SOI_priorities[x]]) > float(SOI_parameters[x]):
					new_list_matching.append(list1[soi])
			list1 = new_list_matching
			
		elif SOI_filters[x] == "Less than": 
			# Keep Things that Fit Criteria
			new_list_matching = []
			for soi in range(0,len(list1)):
				if float(list1[soi][SOI_priorities[x]]) < float(SOI_parameters[x]):
					new_list_matching.append(list1[soi])
			list1 = new_list_matching
			
		elif SOI_filters[x] == "Containing":			 
			# Keep Things that Fit Criteria
			new_list_matching = []
			for soi in range(0,len(list1)):
				if list1[soi][0] in SOI_parameters[x]:
					new_list_matching.append(list1[soi])
			list1 = new_list_matching 
					
	#print 'Sorted list: {}' .format(list1)
		
		
	# Check if the list is empty
	if len(list1) > 0:
		soi = list1[0]
	else:
		print "No SOI Matches the Criteria"
		soi = []
			
	print 'Selected SOI: {}' .format(soi)	
		
	return soi


def SOI_LibraryCheck( soi ):
	""" Look up the SOI to recommend a best-fit flow graph from the library
	"""

	# There needs to be some kind of look up to limit the possibilities
	# What parameters will be used to search the library? Modulation, Spreading, Frequency, Bandwidth?... How will the search library be managed?
	
	# (Modulation_Type, Modulation_Sub_Parameters, Same_Modulation_Type_Index) : (Flow_Graph_Name, [Default_Variables], [Default_Values], [Potential_Attacks])

	# Find Flow Graphs with Same Modulation Type	
	same_modulation_list_names=[v[0] for k,v in SOI_library.iteritems() if k[0]==soi[0]]  # Look Through Each Key in the Search Dictionary	
	if not same_modulation_list_names:
		same_modulation_list_names = [v[0] for v in SOI_library.values()]
	
	return same_modulation_list_names	

###################################
    

     
if __name__ == '__main__':
    pass
    # print "Testing  Lib Utils with current library..."
    # filename1='/home/user/FISSURE/YAML/library.yaml'
    # with open(filename1) as library:
        # pd_library=yaml.load(library)
    # prots=getProtocols(pd_library)
    # print prots
    # sois = getSOIs(pd_library)
    # print sois
    # demods = getDemodulationFlowGraphs(pd_library)
    # print demods
    # for prot in prots:
       # print "Protocol :", prot
       # pkts=getPacketTypes(pd_library,prot)
       # print "Packets in ", prot, ": ",pkts    
       # for pkt in pkts:
          # flds = getFields(pd_library, prot, pkt)
          # defaults = getDefaults(pd_library, prot, pkt)
          # for i in range(len(flds)):
             # print "Fields ",i, ": ", flds[i], "default = ", defaults[i]
          
    
