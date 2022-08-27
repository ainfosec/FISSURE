/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2014 by Piotr Krysik <ptrkrysik@gmail.com>
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

#define USE_CXX (__cplusplus >= 201103)

#include <vector>
#include <armadillo>
#include <string>
#include <boost/make_shared.hpp>

#include "gnuplot-iostream.h"

std::shared_ptr<Gnuplot> current_figure;

void imagesc(const arma::mat & x){
    Gnuplot gp;
	gp << "set palette rgb 3,2,2;";
   gp << "plot ";
 	gp << gp.file1d(x) << "matrix with image";
	gp << std::endl;
}

void plot(const arma::cx_mat & x, std::string title){
   arma::mat y = arma::abs(x);
   if(current_figure.get()==NULL){
      current_figure = boost::make_shared<Gnuplot>();
   }
   (*current_figure) << "plot ";
   
   (*current_figure) << current_figure->file1d(y) <<"title \'" << title << "\' with lines ";
   (*current_figure) << std::endl; 
}

void replot(const arma::cx_mat & x, std::string title){
   arma::mat y = arma::abs(x);
   if(current_figure.get()==NULL){
      current_figure = boost::make_shared<Gnuplot>();
   }
   (*current_figure) << "replot ";
   (*current_figure) << current_figure->file1d(y) <<"title \'"  << title << "\' with lines ";
   (*current_figure) << std::endl; 
}

template<typename T>
void plot(const std::vector<T> & x){
   arma::cx_mat y = arma::conv_to<arma::cx_mat>::from(x);
   plot(y,"");
}

template<typename T>
void plot(const std::vector<T> & x, std::string title){
   arma::cx_mat y = arma::conv_to<arma::cx_mat>::from(x);
   plot(y,title);
}

template<typename T>
void replot(const std::vector<T> & x, std::string title){
   arma::cx_mat y = arma::conv_to<arma::cx_mat>::from(x);
   replot(y,title);
}

