@ Brief ===================================================================

  	This is Sewio networks opensniffer python 3 module package. It
	serves as wrapper for Open Sniffer configuration webpage.

@ Notes ===================================================================

	* Initial release of the package
	* Package is written for python 3 (must be already installed)
	* For now only works under windows
	* Socket automatically binds to LAN controller address on module 
	  import
	* This API was build and tested on windows 7, since later windowses
	  have more strict socket policies, executing scripts that use this
	  API on them will require elevation.
	* Multiple sniffers can be connected at the same time (via switch
	  for instance) as long as they have different IP address. but note
	  that must have same subnet.
	* Currently only default modulations for each band are used.

@ Dir =====================================================================

	opensniffer /
	|
	|----readme.txt
	|----send.py
	|----receive.py
	|----opensniffer-0.1.zip
	     |
	     |----OpenSniffer-0.1 /
		  |----PKG-INFO
	     	  |----setup.py
	     	  |----opensniffer.py


@ Install =================================================================

	In order to install package (python 2.7 already installed and 
	added to path), unzip OpenSniffer-0.1.zip open command line, 
	cd to OpenSniffer-0.1 dir and run 
	
	> python setup.py install

	In order to test that module works, try one of provided examples

@ Examples ================================================================

	Downloaded zip should contain three examples

	send.py     -> 	Shows how to use sniffer injection mode to send 
			data to selected band, payload and how many times
			it should be sent can be changed.

	receive.py  ->	Shows how to use API to receive data. Band must be 
			selected beforehand (For list of bands scroll 
			down).

@ Class ===================================================================

	No functions are standalone. In order to begin create OpenSniffer 
	class object first (constructor takes string coded IP as parameter)

	> sniffer = OpenSniffer('10.10.10.2')

	* Note that due to fact how windows work, it would be unpractical
	to change socket address during script execution. Unfortunalety
	this means, that if any different address is required following
	steps must be done:

	1. 	Go to Open Sniffer website in browser and in settings 
		change IP address to desired, also change gateway and host
		IP address (they must be same). This is the initial
		release of the API, for right now please use default UDP
		port 17754, since API currently does not have means of
		changing it from default.

	2.	In Win go to Control panel -> Network and sharing Center ->
		Change adapter settings -> right click on Local Area 
		Connection -> Properties -> left click onInternet Protocol
		Version 4 -> Properties -> Hit use following IP address and
		change IP adress to one that's been used as both gateway 
		and host address on open sniffer -> hit ok.

	3. 	API currently works in a way, that on module import python
		finds out current LAN IP address and binds to it.

@ Methods =================================================================
	 

	This reference gives overview of curently available class methods 
	
	def __init__(self, address):
		
		@ Brief
			Construtor, it's called on instance creation, 
			obtains basic data from sniffer with given 
			address. (IP, MAC, FW).
		
		@ Param
			address     -> 	string coded IP Address of Open 
					Sniffer

		@ Example
			sniffer = OpenSniffer('10.10.10.2')

	def getInfo(self):
		
		@ Brief
			Gets data from Open Sniffer (MAC, FW), is called in
			constuctor, so new instances already know who they
			are.

		@ Example
			sniffef.getInfo()
	
	def setBand(self, band):
		
		@ Brief
			Sets band to listen on when using readBytes method
			
		@ Param
			band 	    -> 	One of the macros that are at the 
					bottom of this file must be used.

		@ Return
			Bool (True if change successful, False otherwise)		
		
		@ Example
			sniffer.setBand(EUROPE868)

	def injectBytes(self, band, repeat=100, payload='010203'):
		
		@ Brief
			Injects given payload, given number times on given 
			band (default '010203' hundred times) 	
			
		@ Param
			band        -> 	One of the bands (list at bottom)
					must be suplied.
			repeat      -> 	Number of times to send payload 
					default vale = 100
			payload	    ->	String coded hexadecimal
					representation of bytes to use as
					payload default = '010203'			

		@ Return
			Bool (True if injected properly, False otherwise)		

		@ Example
			# Sends 0x01 0x02 0x03 hundred times 
			sniffer.injectBytes(ISM2405)

			# Sends 0xAA 0xBB 0xCC twenty times
			sniffer.injectBytes(AMERICA906, 20, 'AABBCC')

	def readBytes(self, num):
		
		@ Brief
			Returns up to given number of bytes at band that
			has to be selected in advance by calling setBand.
			This function is non-blocking and returns what's 
			available in socket immediately. In orded to
			Receive larger chunks it's advised to use multiple
			calls and append data together.

		@ Param
			num	    ->	Number of bytes that should be read
					(due to way how sockets work, it is
					advised to use factors of 2 eg 128)
		
		@ Return
			String (String coded hexadecimal, if no bytes are 
				read returns '')			
						
		@ Example
			sniffer.readBytes(1024)

@ Variables ===============================================================

	Class variables unique for each sniffer
	
	sniffer.IP  -> 	String coded Open Sniffer IP Address.
	sniffer.MAC ->	String coded Open Sniffer MAC Address.
	sniffer.FW  ->  String coded Open Sniffer current FW version.

@ Bands ===================================================================
	
	Band macros are in format XY wheye X is region and Y is frequency
	* note right now only default modulation for each band is available

	@ Chinese bands

		CHINA780, CHINA782, CHINA784, CHINA786

	@ European band

		EUROPE868

	@ American bands

		AMERICA906, AMERICA908, AMERICA910, AMERICA912, AMERICA914,
		AMERICA916, AMERICA918, AMERICA920, AMERICA922, AMERICA924

	@ ISM2.4GHZ band

		ISM2405, ISM2410, ISM2415, ISM2420, ISM2425, ISM2430
		ISM2435, ISM2440, ISM2445, ISM2450, ISM2455, ISM2460
		ISM2465, ISM2470, ISM2475, ISM2480
