CXXFLAGS=-O3 
rtl_zwave: rtl_zwave.o wireshark.o popen2.o
	$(CXX) -o $@  $^ $(LDFLAGS)


clean:
	rm -f rtl_zwave.o wireshark.o popen2.o rtl_zwave
