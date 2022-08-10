library(TTR)
library(ggplot2)

### test file
in.file <- file('/tmp/ofdm.bin', 'rb')

sig <- readBin(in.file, double(), n=10000, size=4, endian='little')

sig <- sig[seq(1, length(sig), 2)] + 1i * sig[seq(2, length(sig), 2)]

pow <- abs(sig)^2

plot(SMA(pow, 1600), type='l')
