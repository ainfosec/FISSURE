from .css_constants import *
import numpy as np


class physical_layer:
    def __init__(self, slow_rate=False, phy_packetsize_bytes=18, nframes=1, chirp_number=1):
        self.slow_rate = slow_rate
        self.phy_packetsize_bytes = phy_packetsize_bytes if phy_packetsize_bytes <= max_phy_packetsize_bytes else max_phy_packetsize_bytes
        self.nframes = nframes
        self.chirp_number = chirp_number
        self.bits_per_symbol = 6 if self.slow_rate is True else 3
        self.codewords = codewords_250kbps if self.slow_rate is True else codewords_1mbps
        self.coderate = 3.0 / 4 if self.slow_rate is False else 3.0 / 16
        self.intlv_seq = intlv_seq if self.slow_rate is True else []
        self.preamble = preamble_250kbps if self.slow_rate is True else preamble_1mbps
        self.SFD = SFD_250kbps if self.slow_rate is True else SFD_1mbps
        self.PHR = self.gen_PHR()
        self.rcfilt = self.gen_rcfilt()
        self.possible_chirp_sequences = self.gen_chirp_sequences()
        if self.chirp_number < 1 or self.chirp_number > 4:
            print("Invalid chirp sequence number, must be [1..4]. Use chirp 1")
            self.chirp_number = 1
        self.chirp_seq = self.possible_chirp_sequences[self.chirp_number - 1]
        self.n_subchirps = 4;
        self.n_tau = n_tau[self.chirp_number - 1]
        self.time_gap_1 = np.zeros((n_chirp - 2 * self.n_tau - self.n_subchirps * n_sub,),
                                   dtype=np.complex128)
        self.time_gap_2 = np.zeros((n_chirp + 2 * self.n_tau - self.n_subchirps * n_sub,),
                                   dtype=np.complex128)
        self.padded_zeros = self.calc_padded_zeros()
        self.nsym_frame = self.calc_nsym_frame()
        self.nsamp_frame = self.calc_nsamp_frame(self.nsym_frame)

    def calc_nsym_frame(self):
        nbits_payload = len(self.PHR) + self.phy_packetsize_bytes * 8 + self.padded_zeros
        nsym_payload = float(nbits_payload) / 2 / self.coderate
        nsym_header = len(self.preamble) + len(self.SFD)
        nsym_frame = nsym_header + nsym_payload
        return int(nsym_frame)


    def calc_nsamp_frame(self, nsym_frame):
        nchirps = nsym_frame / 4
        if nchirps % 2 == 0:
            return int(nchirps * n_chirp)
        else:
            return int((nchirps - 1) * n_chirp + 4 * n_sub + len(self.time_gap_1))

    def calc_padded_zeros(self):
        if self.slow_rate == True:
            k = np.ceil(1.0 / 3 * self.phy_packetsize_bytes + 0.5)
            p = 24 * k - 12 - 2 * self.phy_packetsize_bytes
        else:
            k = np.ceil(4.0 / 3 * self.phy_packetsize_bytes) + 2
            p = 6 * k - 8*self.phy_packetsize_bytes - 12
        return int(p)

    def gen_rcfilt(self):
        alpha = 0.25
        rcfilt = np.ones((n_sub,))
        half_plateau_width = round((1 - alpha) / (1 + alpha) * n_sub / 2)
        rcfilt[int(len(rcfilt) / 2 + half_plateau_width):] = [
            0.5 * (1 + np.cos((1 + alpha) * np.pi / (alpha * n_sub) * i)) for i in
            range(int(n_sub / 2 - half_plateau_width))]
        rcfilt[0:int(len(rcfilt) / 2 - half_plateau_width)] = rcfilt[-1:int(len(rcfilt) / 2 + half_plateau_width - 1):-1]
        # force 0s at the edges
        rcfilt[0] = 0
        rcfilt[-1] = 0
        return rcfilt

    def gen_chirp_sequences(self):
        # generate subchirps
        subchirp_low_up = np.array([np.exp(1j * (
        -2 * np.pi * fc + mu / 2 * i / bb_samp_rate) * i / bb_samp_rate)
                                    for i in np.arange(n_sub) - n_sub / 2])
        subchirp_low_down = np.array([np.exp(1j * (
        -2 * np.pi * fc - mu / 2 * i / bb_samp_rate) * i / bb_samp_rate)
                                      for i in np.arange(n_sub) - n_sub / 2])
        subchirp_high_up = np.array([np.exp(1j * (
        +2 * np.pi * fc + mu / 2 * i / bb_samp_rate) * i / bb_samp_rate)
                                     for i in np.arange(n_sub) - n_sub / 2])
        subchirp_high_down = np.array([np.exp(1j * (
        +2 * np.pi * fc - mu / 2 * i / bb_samp_rate) * i / bb_samp_rate)
                                       for i in np.arange(n_sub) - n_sub / 2])

        # multiply each subchirp with the raised cosine window
        subchirp_low_up *= self.rcfilt
        subchirp_low_down *= self.rcfilt
        subchirp_high_up *= self.rcfilt
        subchirp_high_down *= self.rcfilt

        # put together the chirp sequences (without DQPSK symbols)
        chirp_seq_I = np.concatenate((subchirp_low_up, subchirp_high_up, subchirp_high_down, subchirp_low_down))
        chirp_seq_II = np.concatenate((subchirp_high_up, subchirp_low_down, subchirp_low_up, subchirp_high_down))
        chirp_seq_III = np.concatenate((subchirp_low_down, subchirp_high_down, subchirp_high_up, subchirp_low_up))
        chirp_seq_IV = np.concatenate((subchirp_high_down, subchirp_low_up, subchirp_low_down, subchirp_high_up))

        return [chirp_seq_I, chirp_seq_II, chirp_seq_III, chirp_seq_IV]

    def gen_PHR(self):
        PHR = np.zeros((12,), dtype=int)
        payl_len_bitstring = '{0:07b}'.format(self.phy_packetsize_bytes)
        payl_len_list = [int(payl_len_bitstring[i], 2) for i in range(0, len(payl_len_bitstring))]
        PHR[0:7] = payl_len_list
        return PHR
