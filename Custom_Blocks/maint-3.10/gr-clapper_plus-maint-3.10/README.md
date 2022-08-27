# gr-clapper_plus

This GNU Radio out-of-tree module will toggle a Clapper Plus device by transmitting 433 MHz on-off keying (OOK) signals. The Clapper Plus has more than one version and frequency band. The one used during testing has a remote with two buttons to control power for two electrical devices. The main difference in the signaling between the two buttons is the amount of time between bursts. The same signal for turning a switch on can be used to turn it off as long as there is a sufficient time interval between them.

This software has been integrated into [FISSURE: The RF Framework](https://github.com/ainfosec/FISSURE).

The remote: 

![Clapper Remote](/examples/Clapper_Plus_915_Remote.png)

A sequence of bursts (zoomed out):

![Clapper Signal Zoom Out](/examples/Clapper_Plus_433_time.png)

A single burst with 22 pulses (zoomed in):

![Clapper Signal Zoom In](/examples/Clapper_Plus_433_zoom.png)

My notes:

![Clapper Notes](/examples/Clapper_Plus_433.png)
