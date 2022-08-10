//
// Copyright 2010 Ettus Research LLC
// Copyright 2018 Ettus Research, a National Instruments Company
//
// SPDX-License-Identifier: GPL-3.0-or-later
//

#ifndef ASCII_ART_DFT_HPP
#define ASCII_ART_DFT_HPP

#include <string>
#include <cstddef>
#include <vector>
#include <complex>
#include <stdexcept>

namespace ascii_art_dft{

    //! Type produced by the log power DFT function
    typedef std::vector<float> log_pwr_dft_type;

    /*!
     * Get a logarithmic power DFT of the input samples.
     * Samples are expected to be in the range [-1.0, 1.0].
     * \param samps a pointer to an array of complex samples
     * \param nsamps the number of samples in the array
     * \return a real range of DFT bins in units of dB
     */
    template <typename T> log_pwr_dft_type log_pwr_dft(
        const std::complex<T> *samps, size_t nsamps
    );

    /*!
     * Convert a DFT to a piroundable ascii plot.
     * \param dft the log power dft bins
     * \param width the frame width in characters
     * \param height the frame height in characters
     * \param samp_rate the sample rate in Sps
     * \param dc_freq the DC frequency in Hz
     * \param dyn_rng the dynamic range in dB
     * \param ref_lvl the reference level in dB
     * \return the plot as an ascii string
     */
    std::string dft_to_plot(
        const log_pwr_dft_type &dft,
        size_t width,
        size_t height,
        double samp_rate,
        double dc_freq,
        float dyn_rng,
        float ref_lvl
    );

} //namespace ascii_dft

/***********************************************************************
 * Implementation includes
 **********************************************************************/
#include <cmath>
#include <sstream>
#include <algorithm>

/***********************************************************************
 * Helper functions
 **********************************************************************/
namespace {/*anon*/

    static const double pi = double(std::acos(-1.0));

    //! Round a floating-point value to the nearest integer
    template <typename T> int iround(T val){
        return (val > 0)? int(val + 0.5) : int(val - 0.5);
    }

    //! Pick the closest number that is nice to display
    template <typename T> T to_clean_num(const T num){
        if (num == 0) return 0;
        const T pow10 = std::pow(T(10), int(std::floor(std::log10(std::abs(num)))));
        const T norm = std::abs(num)/pow10;
        static const int cleans[] = {1, 2, 5, 10};
        int clean = cleans[0];
        for (size_t i = 1; i < sizeof(cleans)/sizeof(cleans[0]); i++){
            if (std::abs(norm - cleans[i]) < std::abs(norm - clean))
                clean = cleans[i];
        }
        return ((num < 0)? -1 : 1)*clean*pow10;
    }

    //! Compute an FFT with pre-computed factors using Cooley-Tukey
    template <typename T> std::complex<T> ct_fft_f(
        const std::complex<T> *samps, size_t nsamps,
        const std::complex<T> *factors,
        size_t start = 0, size_t step = 1
    ){
        if (nsamps == 1) return samps[start];
        std::complex<T> E_k = ct_fft_f(samps, nsamps/2, factors+1, start,      step*2);
        std::complex<T> O_k = ct_fft_f(samps, nsamps/2, factors+1, start+step, step*2);
        return E_k + factors[0]*O_k;
    }

    //! Compute an FFT for a particular bin k using Cooley-Tukey
    template <typename T> std::complex<T> ct_fft_k(
        const std::complex<T> *samps, size_t nsamps, size_t k
    ){
        //pre-compute the factors to use in Cooley-Tukey
        std::vector<std::complex<T> > factors;
        for (size_t N = nsamps; N != 0; N /= 2){
            factors.push_back(std::exp(std::complex<T>(0, T(-2*pi*k/N))));
        }
        return ct_fft_f(samps, nsamps, &factors.front());
    }

    //! Helper class to build a DFT plot frame
    class frame_type{
    public:
        frame_type(size_t width, size_t height):
            _frame(width-1, std::vector<char>(height, ' '))
        {
            /* NOP */
        }

        //accessors to parts of the frame
        char &get_plot(size_t b, size_t z){return _frame.at(b+albl_w).at(z+flbl_h);}
        char &get_albl(size_t b, size_t z){return _frame.at(b)       .at(z+flbl_h);}
        char &get_ulbl(size_t b)          {return _frame.at(b)       .at(flbl_h-1);}
        char &get_flbl(size_t b)          {return _frame.at(b+albl_w).at(flbl_h-1);}

        //dimension accessors
        size_t get_plot_h(void) const{return _frame.front().size() - flbl_h;}
        size_t get_plot_w(void) const{return _frame.size() - albl_w;}
        size_t get_albl_w(void) const{return albl_w;}

        std::string to_string(void){
            std::stringstream frame_ss;
            for (size_t z = 0; z < _frame.front().size(); z++){
                for (size_t b = 0; b < _frame.size(); b++){
                    frame_ss << _frame[b][_frame[b].size()-z-1];
                }
                frame_ss << std::endl;
            }
            return frame_ss.str();
        }

    private:
        static const size_t albl_w = 6, flbl_h = 1;
        std::vector<std::vector<char> > _frame;
    };

} //namespace /*anon*/

/***********************************************************************
 * Implementation code
 **********************************************************************/
namespace ascii_art_dft{

    //! skip constants for amplitude and frequency labels
    static const size_t albl_skip = 5, flbl_skip = 20;

    template <typename T> log_pwr_dft_type log_pwr_dft(
        const std::complex<T> *samps, size_t nsamps
    ){
        if (nsamps & (nsamps - 1))
            throw std::runtime_error("num samps is not a power of 2");

        //compute the window
        double win_pwr = 0;
        std::vector<std::complex<T> > win_samps;
        for(size_t n = 0; n < nsamps; n++){
            //double w_n = 1;
            //double w_n = 0.54 //hamming window
            //    -0.46*std::cos(2*pi*n/(nsamps-1))
            //;
            double w_n = 0.35875 //blackman-harris window
                -0.48829*std::cos(2*pi*n/(nsamps-1))
                +0.14128*std::cos(4*pi*n/(nsamps-1))
                -0.01168*std::cos(6*pi*n/(nsamps-1))
            ;
            //double w_n = 1 // flat top window
            //    -1.930*std::cos(2*pi*n/(nsamps-1))
            //    +1.290*std::cos(4*pi*n/(nsamps-1))
            //    -0.388*std::cos(6*pi*n/(nsamps-1))
            //    +0.032*std::cos(8*pi*n/(nsamps-1))
            //;
            win_samps.push_back(T(w_n)*samps[n]);
            win_pwr += w_n*w_n;
        }

        //compute the log-power dft
        log_pwr_dft_type log_pwr_dft;
        for(size_t k = 0; k < nsamps; k++){
            std::complex<T> dft_k = ct_fft_k(&win_samps.front(), nsamps, k);
            log_pwr_dft.push_back(float(
                + 20*std::log10(std::abs(dft_k))
                - 20*std::log10(T(nsamps))
                - 10*std::log10(win_pwr/nsamps)
                + 3
            ));
        }

        return log_pwr_dft;
    }

    std::string dft_to_plot(
        const log_pwr_dft_type &dft_,
        size_t width,
        size_t height,
        double samp_rate,
        double dc_freq,
        float dyn_rng,
        float ref_lvl
    ){
        frame_type frame(width, height); //fill this frame

        //re-order the dft so dc in in the center
        const size_t num_bins = dft_.size() - 1 + dft_.size()%2; //make it odd
        log_pwr_dft_type dft(num_bins);
        for (size_t n = 0; n < num_bins; n++){
            dft[n] = dft_[(n + num_bins/2)%num_bins];
        }

        //fill the plot with dft bins
        for (size_t b = 0; b < frame.get_plot_w(); b++){
            //indexes from the dft to grab for the plot
            const size_t n_start = std::max(iround(double(b-0.5)*(num_bins-1)/(frame.get_plot_w()-1)), 0);
            const size_t n_stop  = std::min(iround(double(b+0.5)*(num_bins-1)/(frame.get_plot_w()-1)), int(num_bins));

            //calculate val as the max across points
            float val = dft.at(n_start);
            for (size_t n = n_start; n < n_stop; n++) val = std::max(val, dft.at(n));

            const float scaled = (val - (ref_lvl - dyn_rng))*(frame.get_plot_h()-1)/dyn_rng;
            for (size_t z = 0; z < frame.get_plot_h(); z++){
                static const std::string syms(".:!|");
                if      (scaled-z > 1) frame.get_plot(b, z) = syms.at(syms.size()-1);
                else if (scaled-z > 0) frame.get_plot(b, z) = syms.at(size_t((scaled-z)*syms.size()));
            }
        }

        //create vertical amplitude labels
        const float db_step = to_clean_num(dyn_rng/(frame.get_plot_h()-1)*albl_skip);
        for (
            float db = db_step*(int((ref_lvl - dyn_rng)/db_step));
            db      <=  db_step*(int(ref_lvl/db_step));
            db      +=  db_step
        ){
            const int z = iround((db - (ref_lvl - dyn_rng))*(frame.get_plot_h()-1)/dyn_rng);
            if (z < 0 or size_t(z) >= frame.get_plot_h()) continue;
            std::stringstream ss; ss << db; std::string lbl = ss.str();
            for (size_t i = 0; i < lbl.size() and i < frame.get_albl_w(); i++){
                frame.get_albl(i, z) = lbl[i];
            }
        }

        //create vertical units label
        std::string ulbl = "dBfs";
        for (size_t i = 0; i < ulbl.size(); i++){
            frame.get_ulbl(i+1) = ulbl[i];
        }

        //create horizontal frequency labels
        const double f_step = to_clean_num(samp_rate/frame.get_plot_w()*flbl_skip);
        for (
            double freq = f_step*int((-samp_rate/2/f_step));
            freq       <= f_step*int((+samp_rate/2/f_step));
            freq       += f_step
        ){
            const int b = iround((freq + samp_rate/2)*(frame.get_plot_w()-1)/samp_rate);
            std::stringstream ss; ss << (freq+dc_freq)/1e6 << "MHz"; std::string lbl = ss.str();
            if (b < int(lbl.size()/2) or b + lbl.size() - lbl.size()/2 >= frame.get_plot_w()) continue;
            for (size_t i = 0; i < lbl.size(); i++){
                frame.get_flbl(b + i - lbl.size()/2) = lbl[i];
            }
        }

        return frame.to_string();
    }
} //namespace ascii_dft

#endif /*ASCII_ART_DFT_HPP*/

/*

//example main function to test the dft

#include <iostream>
#include <cstdlib>
#include <curses.h>

int main(void){
    initscr();

    while (true){
        clear();

        std::vector<std::complex<float> > samples;
        for(size_t i = 0; i < 512; i++){
            samples.push_back(std::complex<float>(
                float(std::rand() - RAND_MAX/2)/(RAND_MAX)/4,
                float(std::rand() - RAND_MAX/2)/(RAND_MAX)/4
            ));
            samples[i] += 0.5*std::sin(i*3.14/2) + 0.7;
        }

        ascii_art_dft::log_pwr_dft_type dft;
        dft = ascii_art_dft::log_pwr_dft(&samples.front(), samples.size());

        printw("%s", ascii_art_dft::dft_to_plot(
            dft, COLS, LINES,
            12.5e4, 2.45e9,
            60, 0
        ).c_str());

        sleep(1);
    }


    endwin();
    std::cout << "here\n";
    return 0;
}

*/

