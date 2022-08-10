// gcc -o demo demo_fft.c -lfftw3 -lm
// ./demo  > t
// gnuplot
//     pl 't'
// # DC is at sample 1 and Nyquist frequency at half position == Matlab

#include<math.h>
#include<time.h>
#include<fftw3.h>
#define fe 48000
#define N 8192

#define frequency  4000

int main()
{int k,t;
 fftw_complex *_c2400, *_fc2400;
 fftw_plan plan_2400;
 _c2400    = (fftw_complex *) fftw_malloc (sizeof (fftw_complex) * N);
 _fc2400   = (fftw_complex *) fftw_malloc (sizeof (fftw_complex) * N);
 for (t=0;t<40;t++)                                    // exp(j*2*pi*frequency/fe*t) 
    {_c2400[t][0]=cos((float)t*frequency/fe*2*M_PI); 
     _c2400[t][1]=sin((float)t*frequency/fe*2*M_PI); 
    }
 for (t=40;t<N;t++) {_c2400[t][0]=0.;_c2400[t][1]=0.;} // zero padding
 plan_2400=fftw_plan_dft_1d(N, _c2400, _fc2400, FFTW_FORWARD, FFTW_ESTIMATE);
 fftw_execute (plan_2400);
 for (k=0;k<N;k++) 
     printf("%f\n",_fc2400[k][0]*_fc2400[k][0]+_fc2400[k][1]*_fc2400[k][1]);
}
