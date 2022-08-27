from .css_phy import physical_layer

import numpy as np

class modulator(physical_layer):
	def modulate_random(self):
		payload_bits = np.random.randint(0,2,size=(self.nframes*self.phy_packetsize_bytes*8,))
		return self.modulate(payload_bits)

	def modulate(self,bits):
		if len(bits) != self.nframes*self.phy_packetsize_bytes*8:
			raise Exception("Payload length has to be nframes*packetsize_bytes*8="+str(self.nframes*self.phy_packetsize_bytes*8)+", but is " + str(len(bits)))
		payload_total = bits.reshape(self.nframes, self.phy_packetsize_bytes*8)
		complex_baseband_total = np.zeros((0,))
		for n in range(self.nframes):
			# print "process frame", n+1, "/", self.nframes

			#print "- create random payload data and PHR"	
			payload = payload_total[n]
			self.payload = np.concatenate((self.PHR, payload)) # append payload to PHR

			#print "- divide payload up into I and Q stream"
			[self.payload_I, self.payload_Q] = self.demux(self.payload)

			#print "- pad payload with zeros to satisfy block boundaries"
			self.payload_I = self.pad_zeros(self.payload_I)
			self.payload_Q = self.pad_zeros(self.payload_Q)

			#print "- map bits to codewords"
			self.payl_sym_I = self.bits_to_codewords(self.payload_I)
			self.payl_sym_Q = self.bits_to_codewords(self.payload_Q)
		
			if self.slow_rate == True:
				# print "- interleave codewords"
				self.payl_sym_I = self.interleaver(self.payl_sym_I)
				self.payl_sym_Q = self.interleaver(self.payl_sym_Q)

			#print "- create frame structure"
			self.frame_sym_I = self.create_frame(self.payl_sym_I)
			self.frame_sym_Q = self.create_frame(self.payl_sym_Q)

			#print "- modulate DQPSK symbols"
			self.frame_QPSK = self.mod_QPSK(self.frame_sym_I, self.frame_sym_Q)
			self.frame_DQPSK = self.mod_DQPSK(self.frame_QPSK)

			#print "- modulate DQCSK symbols"
			self.frame_DQCSK = self.mod_DQCSK(self.frame_DQPSK)
			complex_baseband_total = np.concatenate((complex_baseband_total,self.frame_DQCSK)) 	
		
		return [bits, complex_baseband_total]		

	def demux(self, in_stream):
		return [in_stream[0::2], in_stream[1::2]]

	def pad_zeros(self, in_stream):
		# the interleaver and codeword generation impose certain conditions on the frame length that need to be satisfied
		padded_zeros = np.zeros((self.padded_zeros,))
		return np.concatenate((in_stream,padded_zeros))

	def bits_to_codewords(self, in_bits):
		in_bits = in_bits.reshape((len(in_bits)/self.bits_per_symbol), self.bits_per_symbol)
		idx = in_bits.dot(1 << np.arange(in_bits.shape[-1] - 1, -1, -1))
		len_cw = len(self.codewords[0])
		cw_serialized = np.array([self.codewords[int(i)] for i in idx])
		cw_serialized = cw_serialized.reshape((len(cw_serialized.flat),))
		return cw_serialized

	def interleaver(self, in_stream):
		len_cw = len(self.codewords[0])
		if len(in_stream) % (2*len_cw) != 0:
			raise Exception("bit interleaver: Input length must be an integer multiple of " + str(len_cw*2))
		n = len(in_stream)/(2*len_cw)
		out_intlv = np.array(np.zeros((len(in_stream),)))
		len_intlv_seq = len(self.intlv_seq)
		for k in range(n):
			for i in range(len_intlv_seq):
				out_intlv[k*len_intlv_seq+i] = in_stream[k*len_intlv_seq + self.intlv_seq[i]]
		return out_intlv

	def create_frame(self, PHR_PPSDU):
		return np.concatenate((self.preamble, self.SFD, PHR_PPSDU))

	def mod_QPSK(self, in_I, in_Q):
		sym_out = []
		QPSK_symbols = [1+0j, 0+1j, 0-1j, -1+0j]
		for i in range(len(in_I)):
			if (in_I[i], in_Q[i]) == (1,1):	
				sym_out.append(QPSK_symbols[0])
			elif (in_I[i], in_Q[i]) == (-1,1):
				sym_out.append(QPSK_symbols[1])
			elif (in_I[i], in_Q[i]) == (1,-1):
				sym_out.append(QPSK_symbols[2])
			elif (in_I[i], in_Q[i]) == (-1,-1):
				sym_out.append(QPSK_symbols[3])
			else:
				print("ERROR in mod_QPSK: Invalid input sequence")
		return sym_out

	def mod_DQPSK(self, in_QPSK):
		# a distance of 4 symbols is used to calculate the phase difference
		# the delay chain is initialized with exp(1j*pi/4)
		delay_chain = np.array([np.exp(1j*np.pi/4) for i in range(4)])
		sym_out = []
		for i in range(len(in_QPSK)):
			sym_out.append(in_QPSK[i]*delay_chain[3])
			delay_chain[1::] = delay_chain[0::-1]
			delay_chain[0] = sym_out[i]
		delay_chain[:] = np.exp(1j*np.pi/4) # reset delay chain
		return sym_out

	def mod_DQCSK(self, in_DQPSK):
		if len(in_DQPSK) % 4 != 0:
			raise Exception("Number of DQPSK input symbols must be a multiple of 4")		
		n_seq = len(in_DQPSK)/self.n_subchirps
		cplx_bb = np.zeros((0,), dtype=np.complex64)
		
		for i in range(n_seq):
			tmp = self.chirp_seq.copy()
			for k in range(self.n_subchirps):
				tmp[k*n_sub:(k+1)*n_sub] *= in_DQPSK[i*self.n_subchirps+k]
			cplx_bb = np.concatenate((cplx_bb, tmp))
			if i%2 == 0:
				cplx_bb = np.concatenate((cplx_bb, self.time_gap_1))
			else:
				cplx_bb = np.concatenate((cplx_bb, self.time_gap_2))
		return cplx_bb








