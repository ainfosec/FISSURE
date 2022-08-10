Stages
======

Sample Rate
-----------
ADSB uses 1 microsecond spacing for the pulse modulation. Data is binary encoded in rising and falling edges of the pulse. So in order to distinguish between a rising or falling edge we require a minimum of 2 samples per microsecond (or 1 sample / 0.5 us).

Calculation: 1 sample / 0.0000005 seconds = 2000000 samples / second

Thus we need a minimum of 2Msps to fully recover the message envelope.

More details: http://www.radartutorial.eu/13.ssr/sr24.en.html


Complex to Mag
--------------
This block simply extracts the amplitude of the signal and returns it as a floating point. As we are dealing with pulse modulation we do not require any other information for demodulation.


Threshold
---------
The Threshold block takes the input signal and allows us to define which level is a 1 (High) and a 0 (Low). It then outputs these and we convert them into UChar (bytes) for our further processing.

Hook up a scope to the output of the Complex to Mag block if you want to see the pulse signal and adjust your threshold values.


Correlate Access Code
---------------------
This block simply looks for the ADSB preamble (see: http://www.radartutorial.eu/13.ssr/sr24.en.html). If it finds the bit sequence of the preamble it adds a tag at that offset. This tag is then used by the ADSB framer to identify the message.


ADSB Framer
-----------
The framer iterates over the tagged preambles and decodes the rising and falling edges of the message payload. It forwards a message with the decoded payload if the decoding yielded a standard or extended format message (length 56 or 112 bits).


ADSB Decoder
------------
Takes the framed message (binary payload) and decodes heading, speed, position, parity check, etc. This is where the "magic" happens.


Message Source & File Sink
--------------------------
Depending on the format you choose on the ADSB Decoder you will receive a binary output with line by line messages. We use the Message Source to turn it into a binary stream. This binary stream can be forwarded to any output sink - by default we send it to STDOUT.

You could for instance use a TCP Sink and send the HEX format output into dump1090 (`./dump1090 --net-only --interactive`) on port 30001. It will then process the messages and you will get a nice map representation if you browse to http://localhost:8080.
