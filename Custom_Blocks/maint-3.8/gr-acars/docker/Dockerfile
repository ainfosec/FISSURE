FROM ubuntu:20.04
MAINTAINER Gwenhael Goavec-Merou <gwenhael.goavec@trabucayre.com>
  
ARG uid=500

RUN apt update

ENV DEBIAN_FRONTEND=noninteractive

RUN ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime \
	&& apt-get install -y tzdata \
	&& dpkg-reconfigure --frontend noninteractive tzdata \
	&& apt dist-upgrade -y \
	&& apt-get install -y \
	build-essential gnuradio gr-osmosdr libgnuradio-osmosdr0.2.0 \
	pkg-config make g++ file cmake liborc-0.4-dev \
	wget cpio unzip rsync bc git swig

RUN cd /tmp && \
	git clone --depth 1 --single-branch git://git.code.sf.net/p/gr-acars/code gr-acars-code && \
	mkdir gr-acars-code/3.8ng/build && \
	cd gr-acars-code/3.8ng/build && \
	cmake -DCMAKE_INSTALL_PREFIX=/usr ../ && make -j4 && make install && \
	cd ../../../ && rm -rf gr-acars-code

RUN groupadd -r -g $uid user && \
	useradd --no-log-init -s /bin/bash -r -g $uid -u $uid user && \
	mkdir /home/user && chown -R user:user /home/user
WORKDIR /home/user
