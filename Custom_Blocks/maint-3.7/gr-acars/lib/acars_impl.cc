/* -*- c++ -*- */
/* 
 * Copyright 2014 <+YOU OR YOUR COMPANY+>.
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

#undef jmfdebug

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "acars_impl.h"
#include<fftw3.h>
#include<time.h>

static const int MIN_IN = 1;    // mininum number of input streams
static const int MAX_IN = 1;    // maximum number of input streams
static const int MIN_OUT = 0;   // minimum number of output streams
static const int MAX_OUT = 0;   // maximum number of output streams

#define NSEARCH 260  // 13 periods * 20 pts/period
#define fe 48000   // sampling frequency
#define CHUNKSIZE 8192
#define MESSAGE 600 // twice the max message size !
#define MAXSIZE (MESSAGE*8/2400*fe) // 48000/2400=20 symbol/bit & 8 bits*260 char=41600

namespace gr {
  namespace acars {

    acars::sptr
    acars::make(float seuil1, char *filename)
    {return gnuradio::get_initial_sptr (new acars_impl(seuil1,filename));}
    
    void
    acars_impl::forecast (int noutput_items, gr_vector_int &ninput_items_required)
    {
        /* <+forecast+> e.g. ninput_items_required[0] = noutput_items */
    }

    int
    acars_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
        const float *in = (const float *) input_items[0];
        float *out = (float *) output_items[0];

 int deb,debut,fin,seuil=3000; // PARAMETRES A AJUSTER
 int k,i,N,t,n;
 char ctmp[MAXSIZE/8];
 double a=0.;
 int b=0,l0=0,memorise;
 fftw_complex mul;
 fftw_plan plan_a, plan_b, plan_R;
 FILE *f;

  N=noutput_items;
  for (k=0;k<N;k++) _d[_Ntot+k]=in[k];
  _Ntot+=N;
  _total+=N;

// if acq==0 && _Ntot <= 8192 : on ne fait rien d'autre que accumuler 
// if acq==1 && _Ntot < MAXSIZE : on ne fait rien d'autre que accumuler
  if ((_acq==0) && (_Ntot>CHUNKSIZE)) { // COMPLETER SI TAILLE INSUFFISANTE : 
                                        // IL FAUT AU MOINS 8192 POINTS
       remove_avgf(_d,_dm,_Ntot,60.);   // c=ones(60,1)/60; dm=conv(d,c);dm=dm(60/2:end-60/2); d=d-dm;

      for (t=0;t<520;t++)  // t=[0:520]; c2400x13=exp(i*t*2400/fe*2*pi);
        {_c2400x13[t][0]=cos((float)t*2400./fe*2*M_PI);
         _c2400x13[t][1]=sin((float)t*2400./fe*2*M_PI);
        }
      for (t=520;t<_Ntot;t++) {_c2400x13[t][0]=0;_c2400x13[t][1]=0;}
      for (k=0;k<_Ntot;k++) {_s[k][0]=(double)_dm[k];_s[k][1]=0.;}
      plan_a=fftw_plan_dft_1d(_Ntot, _c2400x13, _fc2400x13, FFTW_FORWARD, FFTW_ESTIMATE);
      plan_b=fftw_plan_dft_1d(_Ntot, _s, _fd , FFTW_FORWARD, FFTW_ESTIMATE);
      plan_R=fftw_plan_dft_1d(_Ntot, _fd,_ss, FFTW_BACKWARD, FFTW_ESTIMATE);
      fftw_execute (plan_a);
      fftw_execute (plan_b);
      for (k=0;k<_Ntot;k++) 
        {mul[0]=_fc2400x13[k][0]*_fd[k][0]-_fc2400x13[k][1]*_fd[k][1];
         mul[1]=_fc2400x13[k][1]*_fd[k][0]+_fc2400x13[k][0]*_fd[k][1];
         _fd[k][0]=mul[0]/(float)_Ntot;
         _fd[k][1]=mul[1]/(float)_Ntot;
        }
      fftw_execute (plan_R);
      fftw_destroy_plan (plan_a);
      fftw_destroy_plan (plan_b);
      fftw_destroy_plan (plan_R); // s=conv(c2400x13,d);
      a=0.;
      for (k=NSEARCH;k<_Ntot-NSEARCH;k++) 
          if (_ss[k][0]<100000.) // probleme de FFT ?
             if (_ss[k][0]>a) a=_ss[k][0]; // [a,b]=max(real(s)); 
#ifdef jmfdebug
      printf("_Ntot=%d total=%d\tmax=%d\n",_Ntot,_total,(int)a);
#endif
      if (a>(float)seuil) 
         {_acq=1;
#ifdef jmfdebug
          printf("debut %d\n",_total);fflush(stdout);
#endif
         }
         else 
          {
           _Ntot=0;   // on recommmence une nouvelle acq, les 8192 infos n'ont rien donn'e
          }
   } 
   if ((_acq==1) && (_Ntot>MAXSIZE-4*CHUNKSIZE))
      {// printf("\nN=%d",_Ntot);fflush(stdout);
#ifdef jmfdebug
       sprintf(ctmp,"%d.dat",_filenum);_filenum++;
       f=fopen(ctmp,"w");
       for (k=0;k<_Ntot;k++) fprintf(f,"%f\n",_d[k]);
       fclose(f);
#endif
       if (_Ntot < MAXSIZE) 
          acars_dec(_d,_Ntot,_seuil,c2400,s2400,c1200,s1200,_FICHIER);
       else printf("record too large for processing\n");
       _Ntot=0;
       _acq=0;
      }

  // Tell runtime system how many input items we consumed on
  // each input stream.
  consume_each (noutput_items);

  // Tell runtime system how many output items we produced.
  return 0; // noutput_items;
    }

//^^^^^^^^^^^^^^^^^^^^^

    /*
     * The private constructor
     */
acars_impl::acars_impl (float seuil1, char* filename)
      : gr::block ("acars",
	      gr::io_signature::make(MIN_IN, MAX_IN, sizeof (float)),
	      gr::io_signature::make(MIN_OUT, MAX_OUT, sizeof (float))),
              _seuil(seuil1),_filename(filename)
{ int t;
  _pos=0;
  _Ntot=0;
  _total=0;
  _acq=0;           // all memory allocations are performed at init rather
                    // than dyanmically in the processing function: although
  _filenum=0;       // less efficient in terms of memory use, it seems much
  _FICHIER=fopen(filename,"a");  // faster than allocating big arrays for
  set_seuil(seuil1);             // each new sentence processed
  _c2400x13 = (fftw_complex *) fftw_malloc (sizeof (fftw_complex) * MAXSIZE);
  _fc2400x13= (fftw_complex *) fftw_malloc (sizeof (fftw_complex) * MAXSIZE);
  _fd       = (fftw_complex *) fftw_malloc (sizeof (fftw_complex) * MAXSIZE);
  _s        = (fftw_complex *) fftw_malloc (sizeof (fftw_complex) * MAXSIZE);
  _ss       = (fftw_complex *) fftw_malloc (sizeof (fftw_complex) * MAXSIZE);
  _rs12=(float*)malloc(sizeof(float)*(MAXSIZE)/20); // fin20=floor(length(s12)/20)*20;
  _rs24=(float*)malloc(sizeof(float)*(MAXSIZE)/20); // s12=s12(1:fin20);s24=s24(1:fin20);
  _rc12=(float*)malloc(sizeof(float)*(MAXSIZE)/20); // fin20=floor(length(s12)/20)*20;
  _rc24=(float*)malloc(sizeof(float)*(MAXSIZE)/20); // s12=s12(1:fin20);s24=s24(1:fin20);
  _d=(float*)malloc(MAXSIZE*sizeof(float));
  _dm=(float*)malloc(sizeof(float)*MAXSIZE);
  _out=(float*)malloc(sizeof(float)*MAXSIZE);
  _toutd=(char*)malloc(MESSAGE*8);         // bits
  _tout=(char*)malloc(MESSAGE*8);        // bits
  _message=(char*)malloc(MESSAGE); // bytes
  printf("threshold value=%f, filename=%s\n",seuil1,filename);
  for (t=0;t<20;t++)  // t=[0:520]; c2400x13=exp(i*t*2400/fe*2*pi);
    {c2400[t]=cos((float)t*2400./fe*2*M_PI); //  t=[0:20];  % 2400 Hz dans 48 kHz = 20 points/periode 
     s2400[t]=sin((float)t*2400./fe*2*M_PI); //  c2400=exp(i*t*2400/fe*2*pi);
     c1200[t]=cos((float)t*1200./fe*2*M_PI); //  c1200=exp(i*t*1200/fe*2*pi);
     s1200[t]=sin((float)t*1200./fe*2*M_PI);
    }
}

void acars_impl::set_seuil(float seuil1)
{printf("new threshold: %f\n",seuil1);fflush(stdout);
 _seuil=seuil1;
}


    /*
     * Our virtual destructor.
     */
acars_impl::~acars_impl ()
{free(_d);               // all malloced regions must be freed when leaving
 free(_rs12);free(_rs24);free(_rc12);free(_rc24);
 free(_out);
 fftw_free(_c2400x13);
 fftw_free(_fc2400x13);
 fftw_free(_fd);
 fftw_free(_s);
 fftw_free(_ss);
 free(_tout);free(_toutd);
 free(_message);
//  time(&tm);
}

// http://www.scancat.com/Code-30_html_Source/acars.html
void acars_impl::acars_parse(char *message,int ends,FILE *file)
{int k;
 if (ends>12)
    if ((message[0]==0x2b) && (message[1]==0x2a) && // sync
        (message[2]==0x16) && (message[3]==0x16) && // sync
        (message[4]==0x01))                         // Start Of Heading SOH
        {printf("\nAircraft=");fprintf(file,"\nAircraft=");
         for (k=6;k<13;k++) {printf("%c",message[k]);fprintf(file,"%c",message[k]);}
         printf("\n");fprintf(file,"\n");
         if (ends>17) 
            {if (message[17]==0x02) {printf("STX\n");fprintf(file,"STX\n");}
             if (ends>=21) 
                {printf("Seq. No=");fprintf(file,"Seq. No=");
                 for (k=18;k<22;k++) {printf("%02x ",message[k]);fprintf(file,"%02x ",message[k]);}
                 for (k=18;k<22;k++) 
                     if ((message[k]>=32) || (message[k]==0x10) || (message[k]==0x13))
                        {printf("%c",message[k]);fprintf(file,"%c",message[k]);}
                 printf("\n");fprintf(file,"\n");
                 if (ends>=27) 
                    {printf("Flight=");fprintf(file,"Flight=");
                     for (k=22;k<28;k++) {printf("%c",message[k]);fprintf(file,"%c",message[k]);}
                     printf("\n");fprintf(file,"\n");
                     if (ends>=28) 
                        {k=28;
                         do {if (message[k]==0x03) {printf("ETX");fprintf(file,"ETX");}
                                else if ((message[k]>=32) || (message[k]==0x10) || (message[k]==0x13))
                                     {printf("%c",message[k]);fprintf(file,"%c",message[k]);}
                             k++;
                            } while ((k<ends-1) && (message[k-1]!=0x03));
                         printf("\n");fprintf(file,"\n");
                        }
                    }
                }
            }
        }
 fflush(stdout);fflush(file);
}

void acars_impl::remove_avgf(float *d,float *out,int tot_len,const float fil_len)
{int tmp,k;
 float avg=0.;
 for (k=0;k<fil_len;k++) avg+=d[k];
 for (k=0;k<tot_len-fil_len;k++)
     {out[k]=(d[k]-avg/fil_len);
      avg-=d[k];
      avg+=d[k+(int)fil_len];
     }
 for (k=tot_len-(int)fil_len;k<tot_len;k++) out[k]=d[k]-avg/fil_len;
}

void acars_impl::acars_dec(float *d,int N,float seuil,float *c2400,float *s2400,float *c1200,float *s1200,FILE *file)
{
 int fin,k,i,f,t,n;
 float a=0.,max24=0.,seuildyn;
 char c;
 int b=0,l0=0,l0max,go=0;
 time_t tm;
 fftw_complex mul;

 fftw_plan plan_a, plan_b, plan_R;

 time(&tm);
 printf("\n%s",ctime(&tm));
 fprintf(file,"\n%s",ctime(&tm));
#ifdef jmfdebug
 printf("len=%d seuil=%f\n",N,seuil);
 fprintf(file,"len=%d seuil=%f\n",N,seuil);
#endif
 remove_avgf(d,_out,N,60);  // c=ones(60,1)/60; dm=conv(d,c);dm=dm(60/2:end-60/2); d=d-dm;
// for (k=0;k<N;k++) printf("%f %f\n",d[k],out[k]);

 for (t=0;t<520;t++)  // t=[0:520]; c2400x13=exp(i*t*2400/fe*2*pi);
    {_c2400x13[t][0]=cos((float)t*2400./fe*2*M_PI);
     _c2400x13[t][1]=sin((float)t*2400./fe*2*M_PI);
    }
 for (t=520;t<N;t++) {_c2400x13[t][0]=0;_c2400x13[t][1]=0;}
 for (k=0;k<N;k++) {_s[k][0]=(float)_out[k];_s[k][1]=0.;}
 plan_a=fftw_plan_dft_1d(N, _c2400x13, _fc2400x13, FFTW_FORWARD, FFTW_ESTIMATE);
 plan_b=fftw_plan_dft_1d(N, _s, _fd , FFTW_FORWARD, FFTW_ESTIMATE);
 plan_R=fftw_plan_dft_1d(N, _fd,_ss, FFTW_BACKWARD, FFTW_ESTIMATE);
 fftw_execute (plan_a);
 fftw_execute (plan_b);
 for (k=0;k<N;k++) 
    {mul[0]=_fc2400x13[k][0]*_fd[k][0]-_fc2400x13[k][1]*_fd[k][1];
     mul[1]=_fc2400x13[k][1]*_fd[k][0]+_fc2400x13[k][0]*_fd[k][1];
     _fd[k][0]=mul[0]/(float)N;
     _fd[k][1]=mul[1]/(float)N;
    }
 fftw_execute (plan_R);
 fftw_destroy_plan (plan_a);
 fftw_destroy_plan (plan_b);
 fftw_destroy_plan (plan_R); // s=conv(c2400x13,d);
 for (k=0;k<N-NSEARCH;k++) if (_ss[k+NSEARCH-2][0]>a) {a=_ss[k+NSEARCH-2][0];b=k;} // [a,b]=max(real(s)); 
#ifdef jmfdebug
 printf("a=%f b=%d\n",a,b);fprintf(file,"a=%f b=%d\n",a,b);
#endif
 // % plot(d(b-260:b+260)/120,'g');hold on; plot(real(c2400x13),'r');
 b=b%20; // %20; // ajout du -5 car on est cal'es sur cos, et on veut sin (passage a 0)
         // b=mod(b,20);    % revient au debut par pas de 2pi
         // d=d(b+400:end); % bien se caler est fondamental pour la suite 
         //                 % est-il judicieux d'essayer a +/-1 ?

 l0=0;

 for (k=b;k<N-20;k+=20)
    {_rs12[l0]=0.;
     _rs24[l0]=0.;
     _rc12[l0]=0.;
     _rc24[l0]=0.;
     for (t=0;t<20;t++)
       {_rs24[l0]+=((float)_out[k+t]*s2400[t]);
        _rc24[l0]+=((float)_out[k+t]*c2400[t]);
        _rs12[l0]+=((float)_out[k+t]*s1200[t]);
        _rc12[l0]+=((float)_out[k+t]*c1200[t]);
       }
    // printf("%d %f %f %f %f\n",k,rs12[l0],rs24[l0],rc12[l0],rc24[l0]);
    _rs12[l0]=sqrt(_rs12[l0]*_rs12[l0]+_rc12[l0]*_rc12[l0]);
    _rs24[l0]=sqrt(_rs24[l0]*_rs24[l0]+_rc24[l0]*_rc24[l0]);
    if (max24<_rs24[l0]) max24=_rs24[l0];
    // printf("%f %f\n",rs12[l0],rs24[l0]);
    l0++;
    }

 l0max=l0;
 seuildyn=max24*0.45;
#ifdef jmfdebug
 printf("dynamic threshold: %f\n",seuildyn);fprintf(file,"dynamic threshold: %f\n",seuildyn);
#endif
 seuildyn=seuil;
// for (k=0;k<(N-b)/20;k++) printf("%f %f\n",rs12[k],rs24[k]);
//  l0=find((rs24+rs12)>seuil);   % on ne garde que les points utiles  A FAIRE ?
//  rs12=rs12(l0);rs24=rs24(l0);
 l0=500;
 do l0++; while (((_rs24[l0]+_rs12[l0])<1.4*seuildyn)&&(l0<l0max));  // debut
 do l0++; while (((_rs24[l0]+_rs12[l0])>1.4*seuildyn)&&(l0<l0max));  // fin
 fin=l0; // N; // l0;
#ifdef jmfdebug
 printf("end=%d\n",fin);
#endif

 l0=50; 
 do l0++; while ((_rs24[l0]<seuildyn)&&(l0<l0max)); // ll=find(rs24>seuil);ll=ll(1);rs12=rs12(ll:end);rs24=rs24(ll:end);
 do l0++; while ((_rs12[l0]<_rs24[l0])&&(l0<l0max)); // l=find(rs12>rs24);l=l(1);rs12=rs12(l:end);rs24=rs24(l:end);
#ifdef jmfdebug
 printf("first bit=%d\n",l0);
#endif

 if (fin>l0) {
   for (k=l0;k<fin;k++)  // pos12=find(rs12>rs24);pos24=find(rs24>rs12);toutd(pos12)=0;toutd(pos24)=1;
       if ((_rs24[k]>_rs12[k]) && ((k-l0)<(MESSAGE*8))) _toutd[k-l0]=1; else _toutd[k-l0]=0;

   n=0;
   _tout[n]=1;n++; // les deux premiers 1 sont oublie's car on se sync sur 1200
   _tout[n]=1;n++;
   for (k=0;k<fin-l0;k++)
      {if (_toutd[k]==0) _tout[n]=1-_tout[n-1]; else _tout[n]=_tout[n-1];
#ifdef jmfdebug
       printf("%d",_tout[n]);
#endif
       if (n<(MESSAGE*8)) n++;
      }
   fin=n; // length of tout
   n=0;
   for (k=0;k<fin;k+=8) 
       {_message[n]=_tout[k]+_tout[k+1]*2+_tout[k+2]*4+_tout[k+3]*8+_tout[k+4]*16+_tout[k+5]*32+_tout[k+6]*64;
        n++;
       }
   fin=n; // length of message (should be tout/8)
   n=0;
   for (k=0;k<fin;k++) {if (_message[k]==0x2b) n=k;break;} // search for the 1st 0x2b (start of message)
   for (k=n;k<fin;k++) {printf("%02x ",_message[k]);fprintf(file,"%02x ",_message[k]);}
   printf("\n");fprintf(file,"\n");
   for (k=n;k<fin;k++)
       if ((_message[k]>=32) || (_message[k]==13) || (_message[k]==10)) 
           {printf("%c",_message[k]);fprintf(file,"%c",_message[k]);}
   printf("\n");fprintf(file,"\n");fflush(stdout);fflush(file);
   acars_parse(&_message[n],fin-n,file);
  } else printf("end < beginning !\n");
//  printf("\nfinished %s\n\n",ctime(&tm));
}
//^^^^^^^^^^^^^^^^^^^^^

  } /* namespace acars */
} /* namespace gr */


// ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
