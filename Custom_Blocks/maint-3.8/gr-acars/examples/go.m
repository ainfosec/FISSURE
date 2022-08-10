clear
close
pkg load signal
num=2;
fs=48000*24;

x=read_complex_binary('gr-acars_1.152M_2.bin'); % 131.725 = Primary
seuil=10;
  b=firls(256,[0 24000 48000 fs/2]*2/fs,[1 1 0 0]);
  y=filter(b,1,x);
  y=abs(y(1:24:end));   % rectifier (assumes 0-mean value)
  % plot(y);figure      raw data
  clear x
  baseline=seuil*mean(y(1:5000))
  k=find(y>baseline);
  y=y(k(1):k(end));y=y-mean(y);
  % plot(y);figure  % raw AFSK signal

fs=48000;
bps=2400;              % ??? pquoi x2 pour avoir periode de 1200 Hz ?
f2400=exp(j*2*pi*2400*[0:1/fs:1/bps*2]');f2400=f2400(1:end-1);
f1200=exp(j*2*pi*1200*[0:1/fs:1/bps*2]');f1200=f1200(1:end);

%s2400=abs(conv(y,f2400));s2400=s2400(200:end);
%s1200=abs(conv(y,f1200));s1200=s1200(200:end);
%b=firls(256,[0 3400 4500 fs/2]*2/fs,[1 1 0 0]);
%s2400=filter(b,1,s2400);s2400=s2400(200:end);
%s1200=filter(b,1,s1200);s1200=s1200(200:end);

sf=(fft(y));
f2400f=(fft(f2400,length(sf)));
f1200f=(fft(f1200,length(sf)));
sf2400f=sf.*f2400f; % convolution
sf1200f=sf.*f1200f; % convolution
df=fs/length(sf);
fcut=floor(3500/df)
sf2400f(fcut:end-fcut)=0; % low pass filter in Matlab FFT convention
sf1200f(fcut:end-fcut)=0; % low pass filter in Matlab FFT convention
s2400=abs(ifft(sf2400f));
s1200=abs(ifft(sf1200f));
s2400=s2400(100:end);
s1200=s1200(100:end);

figure; plot(s2400);hold on; plot(s1200); legend('2400','1200')
k=find(s2400<0.5*max(s2400));    % end of sync frame
s2400=s2400(k(1):end);%s2400=s2400(21:floor(length(s2400)/20)*20);
s1200=s1200(k(1):end);%s1200=s1200(21:floor(length(s1200)/20)*20);
pos=10;
plot(s2400,'-');hold on; plot(s1200,'-'); legend('2400','1200')
% now clock recovery ...
toutd=[0];
while ((pos<length(s2400)-40) && (pos<length(s1200)-40))
    pos=pos+20;     % 2400 bps @ 48 kHz = 20 samples/bit
    if (s2400(pos)>s1200(pos)) toutd=[toutd 1];else toutd=[toutd 0];end
    if ((s2400(pos)>s1200(pos)) && (s1200(pos+20)>s2400(pos+20)) && (s1200(pos-20)>s2400(pos-20)))
         [m,p]=max(s2400(pos-3:pos+3));
         pos=(pos-3)+p-1;
    end
    if ((s1200(pos)>s2400(pos)) && (s2400(pos+20)>s1200(pos+20)) && (s2400(pos-20)>s1200(pos-20)))
         [m,p]=max(s1200(pos-3:pos+3));
         pos=(pos-3)+p-1;
    end
    if (pos<length(s2400)/8)
       line([pos pos],[0.2 0.8])
       text(pos,0.1,num2str(pos))
    endif
end

n=1;
tout(n)=1; n=n+1; % les deux premiers 1 sontoublies car on se sync sur 1200
tout(n)=1; n=n+1;
for k=1:length(toutd)
   if (toutd(k)==0) 
      tout(n)=1-tout(n-1);
      else tout(n)=tout(n-1);
   endif 
n=n+1;
end
binaire=reshape(tout(1:floor(length(tout)/8)*8),8,floor(length(tout)/8))';
codeasc=binaire(:,1)+binaire(:,2)*2+binaire(:,3)*4+binaire(:,4)*8+binaire(:,5)*16+binaire(:,6)*32+binaire(:,7)*64;
checksomme=1-mod(sum(binaire(:,1:7)')',2); % verification
printf('%02x',codeasc);printf('\n\n');
printf('%c',codeasc);printf('\n\nCRC:');
printf('%d',checksomme-binaire(:,8));printf('\n');

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
clear tout
% now NO clock recovery ...
pos=10
toutd=[0];
while ((pos<length(s2400)-40) && (pos<length(s1200)-40))
    pos=pos+20;     % 2400 bps @ 48 kHz = 20 samples/bit
    if (s2400(pos)>s1200(pos)) toutd=[toutd 1];else toutd=[toutd 0];end
end

n=1;
tout(n)=1; n=n+1; % les deux premiers 1 sontoublies car on se sync sur 1200
tout(n)=1; n=n+1;
for k=1:length(toutd)
   if (toutd(k)==0) 
      tout(n)=1-tout(n-1);
      else tout(n)=tout(n-1);
   endif 
n=n+1;
end
binaire=reshape(tout(1:floor(length(tout)/8)*8),8,floor(length(tout)/8))';
codeasc=binaire(:,1)+binaire(:,2)*2+binaire(:,3)*4+binaire(:,4)*8+binaire(:,5)*16+binaire(:,6)*32+binaire(:,7)*64;
checksomme=1-mod(sum(binaire(:,1:7)')',2); % verification
printf('%02x',codeasc);printf('\n\n');
printf('%c',codeasc);printf('\n\nCRC:');
printf('%d',checksomme-binaire(:,8));printf('\n');
