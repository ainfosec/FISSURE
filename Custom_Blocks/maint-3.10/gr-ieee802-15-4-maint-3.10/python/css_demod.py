from .css_phy import physical_layer
import numpy as np

def c_corrcoef(a,b):
	# formula: sum(a*conj(b))/(sum(a*conj(a))*sum(b*conj(b)))
	num = sum(a*np.conj(b))
	denom = np.sqrt(sum(a*np.conj(a))*sum(b*np.conj(b)))
	if denom == 0: # avoid dividing by 0
		return 0
	return num/denom

class demodulator(physical_layer):
	def demodulate(self, iq_in):
		if len(iq_in) != self.nsamp_frame*self.nframes:
			raise Exception("Demodulator expects "+str(self.nframes)+" frames of length "+str(self.nsamp_frame)+"(="+str(self.nsamp_frame*self.nframes)+"), but input length is "+str(len(iq_in)))
		iq_in = iq_in.reshape(self.nframes, self.nsamp_frame)
		payl_bits_total = np.zeros((0,))
		for i in range(self.nframes):			
			self.sym_DQPSK = self.demod_DQCSK(iq_in[i])	
			self.sym_QPSK = self.demod_DQPSK(self.sym_DQPSK)
			[self.sym_I, self.sym_Q] = self.demod_QPSK(self.sym_QPSK)
			[self.hdr_sym_I, self.payl_sym_I] = self.separate_payload(self.sym_I)
			[self.hdr_sym_Q, self.payl_sym_Q] = self.separate_payload(self.sym_Q)
			if self.slow_rate == True:
				self.payl_sym_I = self.deinterleaver(self.payl_sym_I)
				self.payl_sym_Q = self.deinterleaver(self.payl_sym_Q)
			self.payl_bits_I = self.codewords_to_bits(self.payl_sym_I)
			self.payl_bits_Q = self.codewords_to_bits(self.payl_sym_Q)
			self.payl_bits_I = self.remove_zeropadding(self.payl_bits_I)
			self.payl_bits_Q = self.remove_zeropadding(self.payl_bits_Q)
			self.payl_bits = self.mux(self.payl_bits_I, self.payl_bits_Q)
			payl_bits_total = np.concatenate((payl_bits_total,self.payl_bits[len(self.PHR):]))
		return payl_bits_total	
		
	def demod_DQCSK(self, iq_in):
		len_iq_in = len(iq_in)
		pos = 0
		chirp_seq_ctr = 0
		subchirp_ctr = 0
		subchirps = self.chirp_seq.reshape((4,css_constants.n_sub))
		corr_out = []
		n_sub = css_constants.n_sub
		while len_iq_in - pos >= n_sub:
			tmp = c_corrcoef(iq_in[pos:pos+n_sub], subchirps[subchirp_ctr])
			pos += n_sub
			corr_out.append(tmp)
			subchirp_ctr += 1
			if subchirp_ctr == self.n_subchirps:
				if chirp_seq_ctr == 0: 
					pos += len(self.time_gap_1)
				else:
					pos += len(self.time_gap_2)
				subchirp_ctr = 0
				chirp_seq_ctr = (chirp_seq_ctr + 1) % 2
		return np.array(corr_out)

	def demod_DQPSK(self, sym_in):
		delay_chain = np.conj(np.array([np.exp(1j*np.pi/4) for i in range(4)]))
		sym_out = []
		for i in range(len(sym_in)):
			sym_out.append(sym_in[i]*delay_chain[3])
			delay_chain[1::] = delay_chain[0::-1]
			delay_chain[0] = np.conj(sym_in[i])
		return sym_out

	def demod_QPSK(self, sym_in):
		out_I = np.zeros((len(sym_in),))
		out_Q = np.zeros((len(sym_in),))
		for i in range(len(sym_in)):
			phase = np.angle(sym_in[i], deg=True)
			phase += 360 if phase < 0 else 0
			if phase <= 45 or phase > 315:
				out_I[i] = 1
				out_Q[i] = 1
			elif phase > 45 and phase <= 135:
				out_I[i] = -1
				out_Q[i] = 1
			elif phase > 135 and phase <= 225:
				out_I[i] = -1
				out_Q[i] = -1
			elif phase > 225 and phase <= 315:
				out_I[i] = 1
				out_Q[i] = -1
			else:
				raise Exception("Invalid angle")
		return [np.array(out_I), np.array(out_Q)]

	def separate_payload(self, sym_in):
		len_hdrs = len(self.preamble)+len(self.SFD)
		return [sym_in[:len_hdrs], sym_in[len_hdrs:]]

	def deinterleaver(self, sym_in):
		blocklen = 2*len(self.codewords[0])
		if len(sym_in) % blocklen != 0:
			raise Exception("Interleaver input length must be an integer multiple of "+str(blocklen)+", but is "+str(len(sym_in))+"="+str(blocklen)+"*"+str(float(len(sym_in))/blocklen))
		nblocks = len(sym_in)/blocklen
		sym_out = np.array(np.zeros((len(sym_in),)))
		len_intlv_seq = len(self.intlv_seq)
		for k in range(nblocks):
			for i in range(len_intlv_seq):
				sym_out[k*len_intlv_seq + self.intlv_seq[i]] = sym_in[k*len_intlv_seq+i]
		return sym_out

	def codewords_to_bits(self, sym_in):
		# implements a minimum (Hamming) distance decoder. If there are multiple codewords with the same distance, the first occurrence is chosen
		len_cw =  len(self.codewords[0])
		if len(sym_in) % len_cw != 0:
			raise Exception("Interleaver input length must be an integer multiple of "+str(len_cw)+", but is "+str(len(sym_in))+"="+str(len_cw)+"*"+str(float(len(sym_in))/len_cw))
		sym_in = sym_in.reshape(len(sym_in)/len_cw, len_cw)
		num_cw = len(self.codewords)
		idx_width = int(np.log2(num_cw))
		fmt = "#0"+str(idx_width+2)+"b"
		bits_out = np.zeros((0,))
		for i in range(sym_in.shape[0]):
			d = [0 for k in range(num_cw)]
			for n in range(num_cw):
				d[n] = sum(abs(sym_in[i] - self.codewords[n]))
			min_d = min(d)
			idx = int(d.index(min_d))
			bit_seq = [int(digit) for digit in format(idx,fmt)[2:]]
			bits_out = np.concatenate((bits_out, bit_seq))
		return bits_out

	def remove_zeropadding(self, bits_in):
		return bits_in[:len(bits_in)-self.padded_zeros]

	def mux(self, in_I, in_Q):
		out_bits = np.zeros((2*len(in_I),))
		for i in range(len(in_I)):
			out_bits[2*i] = in_I[i]
			out_bits[2*i+1] = in_Q[i]
		return out_bits




