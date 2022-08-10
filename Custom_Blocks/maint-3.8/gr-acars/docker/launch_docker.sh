docker run --tty --interactive \
	--device /dev/bus/usb \
	--rm -e DISPLAY=$DISPLAY -v /tmp/.X11-unix/:/tmp/.X11-unix \
	-v /dev/dri:/dev/dri \
	-v $(pwd):/home/user ubuntu:gnuradio
