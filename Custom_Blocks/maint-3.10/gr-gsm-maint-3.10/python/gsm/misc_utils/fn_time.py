#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @file
# @author Piotr Krysik <ptrkrysik@gmail.com>
# @section LICENSE
# 
# Gr-gsm is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
# 
# Gr-gsm is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with gr-gsm; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
# 
# 

__hyper_frame = 26*51*2048
__symb_rate = 13.0e6/48.0
__ts_period = 156.25/__symb_rate
__frame_period = 8*__ts_period

#The functions below are crucial part of synchronization between
#transmitter and receiver.

#fnmod_delta computes difference between two frame numbers modulo
#__hyper_frame. The result is correct if difference between the frame
#numbers is not bigger than __hyper_frame/2.
def fnmod_delta(fn1, fn2):
    h2 = __hyper_frame/2
    delta = (fn1%__hyper_frame)-(fn2%__hyper_frame)
    
    if delta >= h2:
        delta = delta - __hyper_frame
    elif delta < -h2:
        delta = delta + __hyper_frame
    
    return delta

def fn_time_diff_delta(fn_x, fn_ref, time_diff_hint=0):
    frames_diff = int(round(time_diff_hint/__frame_period))
    fn_ref_hint = (fn_ref + frames_diff)
    fn_delta = fnmod_delta(fn_x,fn_ref_hint)+frames_diff

    return fn_delta

#fn_time_delta computes difference between reference frame number and a second frame number. It also computes timestamp of the second frame number. The full list of parameters is following:
#* fn_ref - reference frame number modulo __hyper_frame
#* time_ref - precise timestamp of the first sample in the frame fn_ref
#* fn_x - second frame number modulo __hyper_frame,
#* time_hint - coarse time for fn_x that is used as a hint to avoid ambiguities caused by modulo operation applied to frame numbers. The correct are values from range <time2_precise-__hiperframe/2, time2_precise+__hiperframe/2> (where time2_precise is exact time of the first sample in frame fn_x)
#* ts_num - number of timeslot in the frame

def fn_time_delta(fn_ref, time_ref, fn_x, time_hint=None, ts_num=0, ts_ref=0):
    if time_hint is None:
        time_hint = time_ref
        
    time_diff_hint = time_hint-time_ref
    fn_delta = fn_time_diff_delta(fn_x,fn_ref, time_diff_hint)
    time_x_precise = fn_delta*__frame_period+time_ref+(ts_num-ts_ref)*__ts_period
    
    return fn_delta, time_x_precise


if __name__ == "__main__":
    from random import uniform
    from gsm import fn_time_delta_cpp

    fn1 = 10000
    ts_ref = 4
    time1 = 10.5
    for fn2 in range(__hyper_frame//2+fn1-10,__hyper_frame//2*10+fn1+100,10):
        ts_x = int(uniform(0,8))
        time2 = time1 + (fn2-fn1)*__frame_period + (ts_x-ts_ref)*__ts_period
        error = uniform(-6200,6200)
        time2_err = time2+error
        fn_delta, time2_precise = fn_time_delta(fn1, time1, fn2, time2_err, ts_x, ts_ref)
        time2_precise_cpp = fn_time_delta_cpp(fn1, (int(time1),time1-int(time1)), fn2, (int(time2_err),time2_err-int(time2_err)), ts_x, ts_ref)
        if fn_delta != fn2-fn1:
            print("bad fn:", fn2, error)#, 'fn_delta:'+str(fn_delta), time2, error, frames_diff_h4, (time2-time1)/(__hyper_frame*__frame_period), time_diff_hint_h4_prev, time_diff_hint
#        time_diff_hint = time2 - time2_precise
        time_diff_hint = time2_precise_cpp[0]+time2_precise_cpp[1] - time2_precise

        if abs(time_diff_hint) > 0.0001:
            print("time2_precise_cpp",time2_precise_cpp," time2_precise",time2_precise," time_ref",time1," time_hint",time2_err)
            print("")
