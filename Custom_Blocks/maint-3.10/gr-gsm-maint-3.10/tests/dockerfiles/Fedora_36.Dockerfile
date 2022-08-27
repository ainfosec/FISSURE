FROM fedora:36

RUN dnf install -y \
        gcc-c++ \
        make \
        cmake \
        pkgconfig \
        boost-devel \
        spdlog-devel \
        gmp-devel \
        pybind11-devel \
        gnuradio-devel \
        libosmocore-devel \
        gr-osmosdr \
        swig \
        doxygen \
        python3-docutils \
        cppunit-devel \
#deps of libosmocore \
        autoconf \
        automake \
        libtool \
        gnutls-devel \
        libusb-devel \
        libmnl-devel \
        lksctp-tools-devel

ADD https://gitea.osmocom.org/osmocom/libosmocore/archive/1.7.0.tar.gz /src/libosmocore.tar.gz
RUN cd /src/ && \
        tar -xzvf libosmocore.tar.gz && \
        cd libosmocore && \
        autoreconf -if && \
        ./configure --disable-pcsc && \
        make && \
        make install

COPY ./ /src/gr-gsm
WORKDIR /src/gr-gsm/build

RUN cmake .. && \
        # The parallel build sometimes fails when the .grc_gnuradio
        # and .gnuradio directories do not exist
        mkdir $HOME/.grc_gnuradio/ $HOME/.gnuradio/ && \
        make && \
        make -j $(nproc) && \
        make install && \
        ldconfig && \
        make CTEST_OUTPUT_ON_FAILURE=1 test
