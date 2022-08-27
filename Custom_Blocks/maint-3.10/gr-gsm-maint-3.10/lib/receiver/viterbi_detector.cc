/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2009 by Piotr Krysik <ptrkrysik@gmail.com>
 * @section LICENSE
 *
 * Gr-gsm is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * Gr-gsm is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gr-gsm; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

/*
 * viterbi_detector:
 *           This part does the detection of received sequnece.
 *           Employed algorithm is viterbi Maximum Likehood Sequence Estimation.
 *           At this moment it gives hard decisions on the output, but
 *           it was designed with soft decisions in mind.
 *
 * SYNTAX:   void viterbi_detector(
 *                                  const gr_complex * input, 
 *                                  unsigned int samples_num, 
 *                                  gr_complex * rhh, 
 *                                  unsigned int start_state, 
 *                                  const unsigned int * stop_states, 
 *                                  unsigned int stops_num, 
 *                                  float * output)
 *
 * INPUT:    input:       Complex received signal afted matched filtering.
 *           samples_num: Number of samples in the input table.
 *           rhh:         The autocorrelation of the estimated channel 
 *                        impulse response.
 *           start_state: Number of the start point. In GSM each burst 
 *                        starts with sequence of three bits (0,0,0) which 
 *                        indicates start point of the algorithm.
 *           stop_states: Table with numbers of possible stop states.
 *           stops_num:   Number of possible stop states
 *                     
 *
 * OUTPUT:   output:      Differentially decoded hard output of the algorithm: 
 *                        -1 for logical "0" and 1 for logical "1"
 *
 * SUB_FUNC: none
 *
 * TEST(S):  Tested with real world normal burst.
 */

#include <gnuradio/gr_complex.h>
#include <gsm/gsm_constants.h>
#include <cmath>

#define PATHS_NUM (1 << (CHAN_IMP_RESP_LENGTH-1))

void viterbi_detector(const gr_complex * input, unsigned int samples_num, gr_complex * rhh, unsigned int start_state, const unsigned int * stop_states, unsigned int stops_num, float * output)
{
   float increment[8];
   float path_metrics1[16];
   float path_metrics2[16];
   float paths_difference;
   float * new_path_metrics;
   float * old_path_metrics;
   float * tmp;
   float trans_table[BURST_SIZE][16];
   float pm_candidate1, pm_candidate2;
   bool real_imag;
   float input_symbol_real, input_symbol_imag;
   unsigned int i, sample_nr;

/*
* Setup first path metrics, so only state pointed by start_state is possible.
* Start_state metric is equal to zero, the rest is written with some very low value,
* which makes them practically impossible to occur.
*/
   for(i=0; i<PATHS_NUM; i++){
      path_metrics1[i]=(-10e30);
   }
   path_metrics1[start_state]=0;

/*
* Compute Increment - a table of values which does not change for subsequent input samples.
* Increment is table of reference levels for computation of branch metrics:
*    branch metric = (+/-)received_sample (+/-) reference_level
*/
   increment[0] = -rhh[1].imag() -rhh[2].real() -rhh[3].imag() +rhh[4].real();
   increment[1] = rhh[1].imag() -rhh[2].real() -rhh[3].imag() +rhh[4].real();
   increment[2] = -rhh[1].imag() +rhh[2].real() -rhh[3].imag() +rhh[4].real();
   increment[3] = rhh[1].imag() +rhh[2].real() -rhh[3].imag() +rhh[4].real();
   increment[4] = -rhh[1].imag() -rhh[2].real() +rhh[3].imag() +rhh[4].real();
   increment[5] = rhh[1].imag() -rhh[2].real() +rhh[3].imag() +rhh[4].real();
   increment[6] = -rhh[1].imag() +rhh[2].real() +rhh[3].imag() +rhh[4].real();
   increment[7] = rhh[1].imag() +rhh[2].real() +rhh[3].imag() +rhh[4].real();


/*
* Computation of path metrics and decisions (Add-Compare-Select).
* It's composed of two parts: one for odd input samples (imaginary numbers)
* and one for even samples (real numbers).
* Each part is composed of independent (parallelisable) statements like  
* this one:
*      pm_candidate1 = old_path_metrics[0] -input_symbol_imag +increment[2];
*      pm_candidate2 = old_path_metrics[8] -input_symbol_imag -increment[5];
*      paths_difference=pm_candidate2-pm_candidate1;
*      new_path_metrics[1]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
*      trans_table[sample_nr][1] = paths_difference;
* This is very good point for optimisations (SIMD or OpenMP) as it's most time 
* consuming part of this function. 
*/
   sample_nr=0;
   old_path_metrics=path_metrics1;
   new_path_metrics=path_metrics2;
   while(sample_nr<samples_num){
      //Processing imag states
      real_imag=1;
      input_symbol_imag = input[sample_nr].imag();

      pm_candidate1 = old_path_metrics[0] +input_symbol_imag -increment[2];
      pm_candidate2 = old_path_metrics[8] +input_symbol_imag +increment[5];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[0]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][0] = paths_difference;

      pm_candidate1 = old_path_metrics[0] -input_symbol_imag +increment[2];
      pm_candidate2 = old_path_metrics[8] -input_symbol_imag -increment[5];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[1]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][1] = paths_difference;

      pm_candidate1 = old_path_metrics[1] +input_symbol_imag -increment[3];
      pm_candidate2 = old_path_metrics[9] +input_symbol_imag +increment[4];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[2]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][2] = paths_difference;

      pm_candidate1 = old_path_metrics[1] -input_symbol_imag +increment[3];
      pm_candidate2 = old_path_metrics[9] -input_symbol_imag -increment[4];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[3]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][3] = paths_difference;

      pm_candidate1 = old_path_metrics[2] +input_symbol_imag -increment[0];
      pm_candidate2 = old_path_metrics[10] +input_symbol_imag +increment[7];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[4]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][4] = paths_difference;

      pm_candidate1 = old_path_metrics[2] -input_symbol_imag +increment[0];
      pm_candidate2 = old_path_metrics[10] -input_symbol_imag -increment[7];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[5]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][5] = paths_difference;

      pm_candidate1 = old_path_metrics[3] +input_symbol_imag -increment[1];
      pm_candidate2 = old_path_metrics[11] +input_symbol_imag +increment[6];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[6]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][6] = paths_difference;

      pm_candidate1 = old_path_metrics[3] -input_symbol_imag +increment[1];
      pm_candidate2 = old_path_metrics[11] -input_symbol_imag -increment[6];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[7]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][7] = paths_difference;

      pm_candidate1 = old_path_metrics[4] +input_symbol_imag -increment[6];
      pm_candidate2 = old_path_metrics[12] +input_symbol_imag +increment[1];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[8]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][8] = paths_difference;

      pm_candidate1 = old_path_metrics[4] -input_symbol_imag +increment[6];
      pm_candidate2 = old_path_metrics[12] -input_symbol_imag -increment[1];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[9]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][9] = paths_difference;

      pm_candidate1 = old_path_metrics[5] +input_symbol_imag -increment[7];
      pm_candidate2 = old_path_metrics[13] +input_symbol_imag +increment[0];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[10]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][10] = paths_difference;

      pm_candidate1 = old_path_metrics[5] -input_symbol_imag +increment[7];
      pm_candidate2 = old_path_metrics[13] -input_symbol_imag -increment[0];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[11]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][11] = paths_difference;

      pm_candidate1 = old_path_metrics[6] +input_symbol_imag -increment[4];
      pm_candidate2 = old_path_metrics[14] +input_symbol_imag +increment[3];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[12]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][12] = paths_difference;

      pm_candidate1 = old_path_metrics[6] -input_symbol_imag +increment[4];
      pm_candidate2 = old_path_metrics[14] -input_symbol_imag -increment[3];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[13]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][13] = paths_difference;

      pm_candidate1 = old_path_metrics[7] +input_symbol_imag -increment[5];
      pm_candidate2 = old_path_metrics[15] +input_symbol_imag +increment[2];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[14]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][14] = paths_difference;

      pm_candidate1 = old_path_metrics[7] -input_symbol_imag +increment[5];
      pm_candidate2 = old_path_metrics[15] -input_symbol_imag -increment[2];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[15]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][15] = paths_difference;
      tmp=old_path_metrics;
      old_path_metrics=new_path_metrics;
      new_path_metrics=tmp;

      sample_nr++;
      if(sample_nr==samples_num)
         break;

      //Processing real states
      real_imag=0;
      input_symbol_real = input[sample_nr].real();

      pm_candidate1 = old_path_metrics[0] -input_symbol_real -increment[7];
      pm_candidate2 = old_path_metrics[8] -input_symbol_real +increment[0];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[0]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][0] = paths_difference;

      pm_candidate1 = old_path_metrics[0] +input_symbol_real +increment[7];
      pm_candidate2 = old_path_metrics[8] +input_symbol_real -increment[0];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[1]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][1] = paths_difference;

      pm_candidate1 = old_path_metrics[1] -input_symbol_real -increment[6];
      pm_candidate2 = old_path_metrics[9] -input_symbol_real +increment[1];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[2]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][2] = paths_difference;

      pm_candidate1 = old_path_metrics[1] +input_symbol_real +increment[6];
      pm_candidate2 = old_path_metrics[9] +input_symbol_real -increment[1];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[3]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][3] = paths_difference;

      pm_candidate1 = old_path_metrics[2] -input_symbol_real -increment[5];
      pm_candidate2 = old_path_metrics[10] -input_symbol_real +increment[2];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[4]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][4] = paths_difference;

      pm_candidate1 = old_path_metrics[2] +input_symbol_real +increment[5];
      pm_candidate2 = old_path_metrics[10] +input_symbol_real -increment[2];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[5]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][5] = paths_difference;

      pm_candidate1 = old_path_metrics[3] -input_symbol_real -increment[4];
      pm_candidate2 = old_path_metrics[11] -input_symbol_real +increment[3];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[6]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][6] = paths_difference;

      pm_candidate1 = old_path_metrics[3] +input_symbol_real +increment[4];
      pm_candidate2 = old_path_metrics[11] +input_symbol_real -increment[3];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[7]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][7] = paths_difference;

      pm_candidate1 = old_path_metrics[4] -input_symbol_real -increment[3];
      pm_candidate2 = old_path_metrics[12] -input_symbol_real +increment[4];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[8]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][8] = paths_difference;

      pm_candidate1 = old_path_metrics[4] +input_symbol_real +increment[3];
      pm_candidate2 = old_path_metrics[12] +input_symbol_real -increment[4];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[9]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][9] = paths_difference;

      pm_candidate1 = old_path_metrics[5] -input_symbol_real -increment[2];
      pm_candidate2 = old_path_metrics[13] -input_symbol_real +increment[5];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[10]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][10] = paths_difference;

      pm_candidate1 = old_path_metrics[5] +input_symbol_real +increment[2];
      pm_candidate2 = old_path_metrics[13] +input_symbol_real -increment[5];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[11]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][11] = paths_difference;

      pm_candidate1 = old_path_metrics[6] -input_symbol_real -increment[1];
      pm_candidate2 = old_path_metrics[14] -input_symbol_real +increment[6];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[12]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][12] = paths_difference;

      pm_candidate1 = old_path_metrics[6] +input_symbol_real +increment[1];
      pm_candidate2 = old_path_metrics[14] +input_symbol_real -increment[6];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[13]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][13] = paths_difference;

      pm_candidate1 = old_path_metrics[7] -input_symbol_real -increment[0];
      pm_candidate2 = old_path_metrics[15] -input_symbol_real +increment[7];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[14]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][14] = paths_difference;

      pm_candidate1 = old_path_metrics[7] +input_symbol_real +increment[0];
      pm_candidate2 = old_path_metrics[15] +input_symbol_real -increment[7];
      paths_difference=pm_candidate2-pm_candidate1;
      new_path_metrics[15]=(paths_difference<0) ? pm_candidate1 : pm_candidate2;
      trans_table[sample_nr][15] = paths_difference;

      tmp=old_path_metrics;
      old_path_metrics=new_path_metrics;
      new_path_metrics=tmp;

      sample_nr++;
   }

/*
* Find the best from the stop states by comparing their path metrics.
* Not every stop state is always possible, so we are searching in
* a subset of them.
*/
   unsigned int best_stop_state;
   float stop_state_metric, max_stop_state_metric;
   best_stop_state = stop_states[0];
   max_stop_state_metric = old_path_metrics[best_stop_state];
   for(i=1; i< stops_num; i++){
      stop_state_metric = old_path_metrics[stop_states[i]];
      if(stop_state_metric > max_stop_state_metric){
         max_stop_state_metric = stop_state_metric;
         best_stop_state = stop_states[i];
      }
   }

/*
* This table was generated with hope that it gives a litle speedup during
* traceback stage. 
* Received bit is related to the number of state in the trellis.
* I've numbered states so their parity (number of ones) is related
* to a received bit. 
*/
   static const unsigned int parity_table[PATHS_NUM] = { 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0,  };

/*
* Table of previous states in the trellis diagram.
* For GMSK modulation every state has two previous states.
* Example:
*   previous_state_nr1 = prev_table[current_state_nr][0]
*   previous_state_nr2 = prev_table[current_state_nr][1]
*/
   static const unsigned int prev_table[PATHS_NUM][2] = { {0,8}, {0,8}, {1,9}, {1,9}, {2,10}, {2,10}, {3,11}, {3,11}, {4,12}, {4,12}, {5,13}, {5,13}, {6,14}, {6,14}, {7,15}, {7,15},  };

/*
* Traceback and differential decoding of received sequence.
* Decisions stored in trans_table are used to restore best path in the trellis.
*/
   sample_nr=samples_num;
   unsigned int state_nr=best_stop_state;
   unsigned int decision;
   bool out_bit=0;

   while(sample_nr>0){
      sample_nr--;
      decision = (trans_table[sample_nr][state_nr]>0);

      if(decision != out_bit)
         output[sample_nr]=-trans_table[sample_nr][state_nr];
      else
         output[sample_nr]=trans_table[sample_nr][state_nr];

      out_bit = out_bit ^ real_imag ^ parity_table[state_nr];
      state_nr = prev_table[state_nr][decision];
      real_imag = !real_imag;
   }
}
