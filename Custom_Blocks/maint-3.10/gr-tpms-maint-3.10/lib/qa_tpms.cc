/* -*- c++ -*- */
/* 
 * Copyright 2014 Jared Boone <jared@sharebrained.com>.
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

/*
 * This class gathers together all the test cases for the gr-filter
 * directory into a single test suite.  As you create new test cases,
 * add them here.
 */

#include "qa_tpms.h"
#include "qa_ask_env.h"
#include "qa_fixed_length_frame_sink.h"

CppUnit::TestSuite *
qa_tpms::suite()
{
  CppUnit::TestSuite *s = new CppUnit::TestSuite("tpms");
  s->addTest(gr::tpms::qa_ask_env::suite());
  s->addTest(gr::tpms::qa_fixed_length_frame_sink::suite());

  return s;
}
