========
Hardware
========

FISSURE is a tool suite and RF framework consisting of dedicated Python components networked together for the purpose of RF device assessment and vulnerability analysis. FISSURE stemmed from the need to quickly identify and react to unknown devices or devices operating in unidentified modes in a congested RF environment. Over the years it has grown into an in-house laboratory tool used by AIS for nearly all things RF. In addition to its analysis and protocol cataloguing capabilities, it doubles as a repository for tried-and-true code developed by AIS along with popular third-party open-source software tools frequently used by the community. FISSURE can also be used to reliably stage Linux computers and bypass some of the more complicated software installs. FISSURE is continuously growing and while it has an impressive list of capabilities it has yet to reach its full potential. The framework embodies a robust approach and provides easy-to-use mechanisms for adding content. It is expected to always be in a state of maturation to continuously meet the needs of advancing technology.

Concepts
========

FISSURE is intended to support COTS devices and support integration for non-COTS devices.

Supported
=========

The following is a list of "supported" hardware with varying levels of integration:

- USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
- HackRF
- RTL2832U
- 802.11 Adapters
- LimeSDR
- bladeRF, bladeRF 2.0 micro
- Open Sniffer
- PlutoSDR

Configuring
===========

Buttons for: assigning RF-enabled hardware to individual components (USRP B205mini, B210, X300 series; HackRF; bladeRF; LimeSDR; 802.11x Adapters; RTL2832U; Open Sniffer); probing the hardware for diagnostics; and acquiring IP address, daughterboard, and serial number information. 

The hardware information is used to set display items in the Dashboard and pass it to components when running operations that use flow graphs and scripts. Third-party tools do not incorporate information from the hardware buttons.





