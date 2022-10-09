# Updating HackRF Firmware

Firmware is included with each HackRF [release](https://github.com/greatscottgadgets/hackrf/releases). Firmware updates allow for more advanced features like *hackrf_sweep*.
```
hackrf_spiflash -w ~/Installed_by_FISSURE/hackrf-2022.09.1/firmware-bin/hackrf_one_usb.bin
```

# Updating the CPLD

Older versions of HackRF firmware (prior to release 2021.03.1) require an additional step to program a bitstream into the CPLD.

To update the CPLD image, first update the SPI flash firmware, libhackrf, and hackrf-tools to the version you are installing. Then:

```bash
hackrf_cpldjtag -x firmware/cpld/sgpio_if/default.xsvf
```

After a few seconds, three LEDs should start blinking. This indicates that the CPLD has been programmed successfully. Reset the HackRF device by pressing the RESET button or by unplugging it and plugging it back in.
