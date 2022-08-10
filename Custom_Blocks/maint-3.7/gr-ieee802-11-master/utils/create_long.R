
fft.shift <- function(sym) {

	sym <- matrix(sym, ncol=64)

	# the explicit dimensions are required
	# if sym contains only one row
	m1 <- matrix(sym[,33:64], ncol=32)
	m2 <- matrix(sym[, 1:32], ncol=32)

	return(cbind(m1, m2))
}

### symbols as defined in the standard
sym <- c(1, 1, -1, -1, 1, 1, -1, 1, -1, 1, 1, 1, 1, 1, 1, -1, -1, 1, 1, -1, 1, -1, 1, 1, 1, 1, 0, 1, -1, -1, 1, 1, -1, 1, -1, 1, -1, -1, -1, -1, -1, 1, 1, -1, -1, 1, -1, 1, -1, 1, 1, 1, 1)
freq <- c(rep(0, 6), sym, rep(0, 5))

pre <- fft(fft.shift(freq), inverse=T) / sqrt(52)
pre <- Conj(pre)
pre <- rev(pre)


for(i in seq(1, 64, 4)) {
	cat("\t\tgr_complex(", sprintf("% .4f", Re(pre[  i])), ", ", sprintf("% .4f",  Im(pre[  i])), "), ", sep="")
	cat(    "gr_complex(", sprintf("% .4f", Re(pre[i+1])), ", ", sprintf("% .4f",  Im(pre[i+1])), "), ", sep="")
	cat(    "gr_complex(", sprintf("% .4f", Re(pre[i+2])), ", ", sprintf("% .4f",  Im(pre[i+2])), "), ", sep="")
	cat(    "gr_complex(", sprintf("% .4f", Re(pre[i+3])), ", ", sprintf("% .4f",  Im(pre[i+3])), "),\n", sep="")
}
