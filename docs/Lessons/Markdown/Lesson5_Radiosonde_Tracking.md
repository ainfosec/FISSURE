---
Radiosondes are battery-powered telemetry instruments carried into the atmosphere by weather balloon that transmit atmospheric measurements to a ground receiver. Radiosondes can capture altitude, pressure, temperature, relative humidity, wind, cosmic ray readings at high altitude, ozone, and geographical position. They typically transmit between 400-406 MHz or 1680 MHz.

This lesson will show how to:
 - Discover Active Radiosondes Online 
 - Use Tools to Demodulate and Decode the Signals
 - Hunt Radiosondes
 
## Table of Contents
1. [References](#references)
2. [Discovering](#discovering)
3. [Demodulating and Decoding](#demodulating_and_decoding)
4. [Hunting](#hunting)

<div id="references"/> 

## References

- https://en.wikipedia.org/wiki/Radiosonde
- https://sondehub.org/
- https://radiosondy.info/
- https://github.com/projecthorus/radiosonde_auto_rx/wiki
- https://github.com/projecthorus/chasemapper
- https://tracker.habhub.org/
- https://predict.sondehub.org/
- https://predict.habhub.org/

<div id="discovering"/> 

## Discovering

The two primary websites for tracking are SondeHub and the SQ6KXY Radiosonde Tracker. The HabHub Tracker is for amateur high-altitude balloon launches. There are several designated launch areas across the globe and they typically launch twice a day around 0:00 UTC and 12:00 UTC.

SondeHub will show the launch schedules for sites and the radiosonde position as the signals are received and uploaded. Radiosondes will rise in altitude until the balloons burst and then sail with the aid of a parachute. SondeHub will show the path, the telemetry readings, and predict the burst and landing locations.

<div id="demodulating_and_decoding"/> 

## Demodulating and Decoding

**radiosonde_auto_rx**

The _radiosonde\_auto\_rx_ code contains the _auto\_rx_ program which uses RTL SDRs to automatically receive and upload radiosonde positions to multiple services including:
  - The SondeHub Radiosonde Tracker
  - APRS-IS
  - ChaseMapper

The _/radiosonde\_auto\_rx/auto\_rx/station.cfg_ file will allow an operator to control the RTL SDR settings, radiosonde search settings, station location, sondehub upload settings, APRS upload settings, ChaseMapper data output, email notifications, rotator control, logging, web interface settings, debug settings, advanced settings, demodulator/decoder tweaks, and position filtering.

Variables of interest include:
  - gain
  - min_freq/max_freq
  - only_scan
  - station_lat/station_lon
  - uploader_callsign/uploader_antenna
  
The FISSURE menu contains the commands to start _auto\_rx_ (_Tools>>Radiosonde>>radiosonde\_auto\_rx_) and edit the configuration file (_Tools>>Radiosonde>>radiosonde\_auto\_rx Config_).
  
<div id="hunting"/> 

## Hunting

Radiosondes typically stop transmitting after 8 hours or some other set period of time. The batteries may also die out. However, they will still transmit when they are on the ground. A mobile setup is helpful when attempting to retrieve radiosondes. Directional antennas, signal strength measurements, and the decoding tools can help pinpoint the precise location.

SondeHub has a chase car mode that will show your location as well as a means to report a successful recovery to prevent multiple hunters from seeking the same target unawares. The chase car mode can be activated from a phone by clicking the car icon, entering a callsign, and toggling the enable button.

