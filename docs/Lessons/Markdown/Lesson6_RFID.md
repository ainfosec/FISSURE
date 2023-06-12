---
RFID is the wireless non-contact use of radio-frequency electromagnetic fields to transfer data, for the purposes of automatically identifying and tracking tags attached to objects.

A tag is an object that contains electronically stored information. Some tags are powered by and read at short ranges via magnetic fields (passive) and others use a local power source such as a battery (active). Microchips in RFID tags can be read-write or read-only and will not usually exceed 2 KB of data. Tags, like readers, can be made in a variety of sizes and out of different materials depending on the application. The antenna sizes on tags are highly dependent on the frequencies required for particular reading distances.

The RFID tag can be affixed to an object and used to track inventory, assets, people, etc. Unlike a barcode, RFID tags are not required to be visible and can be read hundreds at a time. RFID is used in commerce, transportation and logistics, public transport, infrastructure management and protection, passports, transportation payments, animal and human identification, and sports.

A reader is responsible for reading the RF information from the tags and in many cases is also responsible for transmitting the interrogator signals that trigger the tags. Readers can be found in a variety of forms and can be fixed or mobile. The frequencies for RFID can range from120 kHz to 10 GHz depending on the range required.

This lesson will provide information relating to:
 - RFID Technology and Equipment
 - Using the Proxmark3 to interact with LF/HF cards
 - Running ZEPASSD for reading E-Z Pass information
 
## Table of Contents
1. [References](#references)
2. [RFID Frequencies](#rfid_frequencies)
3. [Near Field Communication](#nfc)
4. [Readers](#readers)
5. [Tags](#tags)
6. [Printers](#printers)
7. [Distributors/Resellers](#distributors)
8. [Standards](#standards)
9. [Protocol and Format](#protocol)
10. [Proxmark3](#proxmark3)
11. [ZEPASSD](#zepassd)

<div id="references"/> 

## References

- https://en.wikipedia.org/wiki/Radio-frequency_identification
- http://rfid.net/
- http://www.rfidjournal.com/
- http://www.gs1.org/sites/default/files/docs/tds/TDS_1_8_Standard_20140203.pdf
- http://www.gs1.org/sites/default/files/docs/uhfc1g2/EPC%20Gen2v2%20Fact%20Sheet.pdf
- https://scund00r.com/all/rfid/2018/06/05/proxmark-cheatsheet.html


<div id="rfid_frequencies"/> 

## RFID Frequencies
The most common RFID applications can be divided into three frequency bands: LF, HF, and UHF. The LF (Low Frequency) range spans from 58-148.5 KHz. This frequency is meant for readers with a short read range (several inches to several feet). The benefit of using this frequency range is that it allows the RF to transmit through metals a few millimeters thick and liquids. This makes this technology suitable for implanting into animals as well as access control and antitheft applications. These tags can be produced at a low cost and are often passive.

The HF (High Frequency) range spans from 1.75-13.56 MHz and the range is similar to LF. HF tags work fairly well on objects made of metal and can work around goods with medium to high water content. The tags are frequently used for proximity applications such as building access, public transportation, electronic payment systems, tracking library books, and patient flow tracking.

The UHF (Ultra High Frequency) range spans the 433, 840-960 MHz, and the 2.4 GHz range. UHF is the most sensitive to interference among the LF, HF, and UHF bands. The UHF tags can be read from inches to 10s of feet in a passive configuration but 100s to 1000s of feet if used semi-passively or actively. The bulk of new RFID projects are using UHF, making UHF the fastest growing segment of the RFID market. Handheld readers used for inventory primarily utilize the 840-960 MHz frequency range.


<div id="nfc"/> 

## Near Field Communication

Near field communication (NFC) is a set of standards for smartphones and similar devices to establish radio communication with each other by touching them or bringing them into proximity usually no more than a few inches. NFC is a branch of HF RFID and an NFC device is capable of being both an NFC reader and an NFC tag. This feature allows NFC devices to communicate peer-to-peer.

NFC standards cover communication protocols and data exchange formats and are based on existing RFID standards including ISO/IEC14443 (proximity cards) and FeliCa (RFID smart card system). The standards for NFC consist of ISO/IEC 18092 and those defined by the NFC Forum which was founded in 2004 by Nokia, NXP Semiconductors, and Sony, and now has more than 160 members. The NFC Forum promotes NFC and certifies device compliance.

NFC operates at 13.56 MHz on ISO/IEC 18000-3 (passive RFID for 13.56 MHz) air interface and at rates ranging from 106 kbit/s to 424 kbit/s. NFC tags contain data and are typically read-only but may be rewriteable. They can be custom-encoded by their manufacturers or use the specifications provided by the NFC Forum. The tags can securely store personal data such as debit and credit card information, loyalty program data, PINs and networking contacts, among other information. Tags currently offer between 96 and 4096 bytes of memory.


<div id="readers"/> 

## Readers

An RFID reader is a device that provides the connection between the tag data and the enterprise system software that needs the information. Readers are responsible for interrogating tags and are made in a variety of forms. Readers can be affixed in a stationary position within a store or factory or integrated into a mobile device such as a portable handheld scanner. There are handheld, fixed, desktop, mobile, wearable, and key fob readers. There are readers with Bluetooth, Wifi, built-in bar code scanners, and computers running a variety of operating systems. Readers can be embedded in electronic equipment or devices and in vehicles.

A reader will always have an RFID module built into it. This module is responsible for all things RFID and will typically be built to follow a protocol. The reader will also consist of an antenna, a power source, and an interface for communications. 

The following sections will list specific RFID readers that are currently on the market focusing mostly on UHF/HF readers. 

### Handheld

Handheld readers provide a mobile solution that is ideal for use in the field for asset tracking and field service applications. The following is a list of companies that have handheld RFID readers and along with some of their models:
- 3M (Sirit): IDentity 5156
- Alien: ALH-9000/9001/9010/9011
- CSL (Convergence Systems Limited): CS101
- Harting: Ha-VIS RFID Handheld RF-M3000
- Honeywell: Optimus 5900
- iDTRONIC: M3 Orange UHF
- Intelleflex
- Intermec: IP30 with CN70/e
- Invengo: XC2900
- Motorola: DS9808R, MC9090-Z, MC9190-Z, MC3190-Z
- Noridc ID: Morphic UHF RFID Cross Dipole, Merlin UHF RFID Cross Dipole
- RaFid Handheld RFID Reader
- TechSigno: 3GScan, PT2SCAN, uSCAN
- TSL: 1097 Bluetooth UHF RFID Reader, 1128 Bluetooth UHF RFID Reader
- Unitech: RH767/8

Types: guns, mobile devices, wearable, snap-on peripherals for mobile computers

The prices for these readers can range from around $1,000 to greater than $10,000 for the high end models. Sometimes the reader is a detachable unit separate from the antenna and handle mechanism.

Motorola readers are a popular choice by industry. This video shows the extent of the MC9090’s durability: https://www.youtube.com/watch?v=wTMePt0jgw4.

### USB, Desktop, Fixed

There are several fixed RFID reader types and they come in several forms. There are cheap solutions in the form of USB sticks or small desktop-sized enclosures that plug into computers via USB or serial connection. There are several fixed position readers that usually serve one specific purpose. These are usually towers, mats, or sensor arrays that log traffic for entryways and gates. The following is a list of companies that have USB, desktop, and fixed RFID readers along with their models:
- 3M (Sirit): INfinity 210
- CAEN RFID: R4300P – ION, R1260I – SLATE
- CSL: CS203 Integrated Ethernet Reader, CS461 Long Range 4 Port Reader, CS468 Long Range 16 Port Reader
- FEIG/OBID: RML-LRU1002, MRU102, MRU200, MRU200i, LRU3000-3500
- Harting: Ha-VIS RFID Reader RF-R500, Ha-VIS RFID Reader RF-R200
- Identive: AUDR
- iDTRONIC: BLUEBOX UHF/HF/LF, Desktop Reader EVO, Stick Reader EVO
- Impinj: Speedway Revolution, Speedway xPortal
- InfoChip: USB Stick Reader
- Invengo: XCRF-860 Reader
- MTI: READ ME (RU-824)
- Nordic ID: Sampo S1, Stix
- SkyeTek: SkyeReader SR70 USB UHF RFID Reader
- SmarTerminal: SmartNL-RF1000, SmartNL-RF2000, SmartNL-RF USB
- Synometrix: SM-1106, SM-2701, SM-8801
- TechSigno: PT2SCAN Wired, SMART PLATE, IDSOFT DESK, UFO ID, WALLY, IDSOFT503
- Tracient Technologies: Explore-R HF
- ThingMagic: USB Plus+ RFID Reader, Astra-EX, Mercury6, Vega

Types: USB stick, desktop, towers, stations, vehicle mounted

There are instances where companies will try to develop their own custom software to interface with the hardware such as the RFIDatawedge from Miles Technologies.

### Bluetooth

Bluetooth RFID readers are useful for pairing with tablets, smartphones, computers, or other readers. This can allow for reader settings and collected data to be handled from other devices at a distance.

Companies that have Bluetooth RFID readers and some of their models:
- Baracoda: orKan RFID, TagRunner Series
- CAEN RFID: A828BT, R1240I – qID, R1170I - qIDmini
- CipherLab: 1861 Handheld RFID Reader
- FEIG/OBID: PRHD102
- Free2Move: FS901-AB0A
- IDBLUE: IDBLUE.UHF, IDBLUE.HF
- InfoChip: Bluetooth Easy Reader
- SmarTerminal: Smart-R400
- TagSense: BlueReader HF, BlueReader UHF
- Tertium Technology: BlueBerry HS UHF, BlueBerry HS HF, BlueBerry iS UHF
- Tracient Technologies: Padl-R HF, Padl-R UF, TP0012
- TSL: 1128 Bluetooth UHF RFID Reader, 1097 Bluetooth UHF RFID and Barcode Wearable Hand Scanner, 1062 Bluetooth HF RFID & Barcode Scanner, 1153 Bluetooth Wearable UHF RFID Reader

Types: key fob, handheld, wearable

### Reader Antennas

Antennas are necessary to direct and amplify signals transmitted and received by the reader. Reader antennas can be built-in for specific products or detachable to suit different applications. The two most common antenna types are linear- and circular-polarized antennas. 

Antennas that radiate linear electric fields have long ranges and high levels of power that enable their signals to penetrate through different materials to read tags. Linear antennas are sensitive to tag orientation; depending on the tag angle or placement, linear antennas can have a difficult time reading tags. Conversely, antennas that radiate circular fields are less sensitive to orientation, but are not able to deliver as much power as linear antennas. 

A circular-polarized antenna reads from a wider angle and a shorter distance than a linear antenna, and it can read tags in different orientations. A circular-polarized antenna can have more consistent read performance and accuracy when the tag orientation is unpredictable.

Choice of antenna is also determined by the distance between the RFID reader and the tags that it needs to read. In near-field applications, the read range is less than 30 cm and the antenna uses magnetic coupling so the reader and tag can transfer power. In near-field systems, the readability of the tags is not affected by the presence of dielectrics such as water and metal in the field. In far-field applications, the range between the tag and reader is greater than 30 cm and can be up to several tens of meters. Far-field antennas utilize electromagnetic coupling and dielectrics can weaken communication between the reader and tags.

For the purposes of office inventory, a circular-polarized antenna would provide the most consistent results due to the unpredictable and inconsistent orientation of tags on pieces of equipment. The increased gain from using a linear antenna should not factor to be a significant advantage due to the relatively close proximity the reader will be to the tags in a typical office environment.

### Development Kits

As of to date (2014) there is no comprehensive review of RFID development kits. The following link discusses a few of the options that were available including UHF options from Impinj, Alien, CAEN, and ThingMagic. 

https://www.rfidjournal.com/question/what-do-i-need-to-know-when-buying-an-rfid-developers-kit

Additionally, there is a Cottonwood UHF reader that can also be considered a development kit.

The author of this lesson worked with a ThingMagic (Division of Trimble) development kit as part of an office inventory study. This development kit had all the criteria needed for the study: an embedded module option, high performance (tag reads and gain), software development options, high level of customer support, sample programs and code, support for multiple geographic regions; antenna, sample tags, and cables all included.

ThingMagic offers development kits that come with or without enclosures that are module specific. The Micro module development kit was selected and it includes the module on a motherboard, AC power adapter, plug adapter kit (US, UK, EU, AUS plugs), antenna (ANT-WB-6-2025), 6' antenna cable, USB cable, packet of sample tags, and instructions for obtaining the SDK/API. The development kit also came with 60 Days of ThingMagic Developer support for the reader type purchased.

The Micro is the smallest 1 W module from ThingMagic that comes with 2 antenna ports. It is controlled by the same Mercury API as all of their products and has been a popular module for applications that require high performance in a small form factor. The module alone costs $395 and the development kit costs $745.

The development kit includes a MT-242025/TRH/A/A (ANT-WB-6-2025) 7.5” monostatic wideband antenna. The antenna is right-hand circularly polarized, has a gain of 7.5 dBic, 3 dB elevation beamwidth of 72 degrees, a 3 dB azimuth beamwidth of 74 degrees, and has a RTNC connector.

### Modules

The module included with the aforementioned development kit is the ThingMagic Micro (M6e-M). The Micro is designed to work in handheld, mobile, and stationary readers. It offers two antenna ports and supports the ability to transmit up to +30 dBm. The FCC limits the maximum power to 4 W EIRP (+36 dBm) with limits on the conducted power from the reader at 30 dBm and an isotropic antenna gain of 6 dBi when being used at 30 dBm. There are edge connections and on-board connectors to allow the module to be soldered directly to a motherboard as a standard component or mated to a motherboard as an add-on option. The module is capable of reading up to 750 tags/second and has a maximum tag read distance of over 30 feet with a 6 dBi antenna.

ThingMagic has produced case studies with Atlas RFID, Avery Dennison, Disney Family Cancer Center, Element ID, Florida State Attorney’s Office, Ford, Greenville Hospital, Lexmark, Lygase, Markem, MediCart, New Balance, ODIN, Sato, Wegmans, and Zebra. Some of these partners have used ThingMagic readers or have embedded them into their products. The following is a partial list of ThingMagic OEM Partners: Ford, Venture Research, Inc., Zebra, Lexmark, Smartsoft Technology Ltd., Ambient ID, QuantumID Technologies (QID), and Seeonic.

These are other companies that offer products that are or are similar to RFID modules: Impinj, iDTRONIC, FEIG Electronic/OBID, 3M (Sirit), Tertium Technology, DLP Design Inc., Harting, Omron Automation and Safety, and Skyetek Inc.


<div id="tags"/> 

## Tags

An RFID tag is comprised of an integrated circuit (called an IC or chip) attached to an antenna that has been printed, etched, stamped or vapor-deposited onto a mount which is often a paper substrate or PolyEthylene Therephtalate (PET). The chip and antenna combo, called an inlay, is then converted or sandwiched between a printed label and its adhesive backing or inserted into a more durable structure. Many of the UHF RFID chips on the market belong to Impinj, Alien, or NXP.

The tag’s chip delivers performance, memory and extended features to the tag. The chip is pre-programmed with a tag identifier (TID); a unique serial number assigned by the chip manufacturer, and includes a memory bank to store the items’ unique tracking identifier (called an electronic product code or EPC). All Gen 2 tags contain the same basic memory features: a 96-256 bit EPC number, a 32-96 bit tag identifier (TID), a 32 bit kill password, a 32 bit access password, and 0-2048+ bits of user memory. 

The electronic product code (EPC) stored in the tag chip’s memory is written to the tag by an RFID printer and takes the form of a 96-bit string of data. The first eight bits are a header which identifies the version of the protocol. The next 28 bits identify the organization that manages the data for this tag; the organization number is assigned by the EPCglobal consortium. The next 24 bits are an object class, identifying the kind of product; the last 36 bits are a unique serial number for a particular tag. These last two fields are set by the organization that issued the tag. The total electronic product code number can be used as a key into a global database to uniquely identify that particular product. However, tags with write capabilities can rewrite the entire EPC memory bank to any value and are not forced to follow a template.

Depending on the chip used and the standards with which that chip complies, the ability to lock specific memory banks, either permanently or temporarily, may exist. If the memory is locked, but not permanently, then it would first need to be unlocked with a password before writing new memory to that block. More information regarding protocol-specific details is presented in later sections. 

Tag antennas collect energy and channel it to the chip to turn it on. Generally, the larger the tag antennas are, the more energy it will be able to collect and channel toward the tag chip, and the further read range the tag will have. Some tags might be optimized for a particular frequency band while others might be tuned for good performance when attached to materials that may not normally work well for wireless communication. 

Tags that have only a single antenna are not as reliable as tags with multiple antennas. With a single antenna, a tag’s orientation can result in areas on the tag where incoming signals cannot be easily harvested to provide sufficient energy to power on the chip and communicate with the reader. Tags with dual antennas require a specialized chip.

### Active Tags

In active RFID systems, tags have their own transmitter and power source. Usually the power source is a battery. Active tags broadcast their own signal to transmit the information stored on their microchips.

Active RFID systems typically operate in the UHF band in order to utilize the longer range. In general, active tags are used on large objects such as rail cars, big reusable containers, and other assets that need to be tracked over long distances.

There are two main types of active tags: transponders and beacons. Transponders are woken up when they receive a radio signal from a reader, and then power on and respond by transmitting a signal back. Because transponders do not actively radiate radio waves until they receive a reader signal, they conserve battery life. 

Beacons are used in most real-time locating systems (RTLS) in order to track the precise location of an asset continuously. Unlike transponders, beacons are not powered on by the reader’s signal. Instead, they emit signals at pre-set intervals. Depending on the level of locating accuracy required, beacons can be set to emit signals every few seconds or once a day. Each beacon’s signal is received by reader antennas that are positioned around the perimeter of the area being monitored, and communicates the tag’s ID information and position.

### Passive Tags

Passive tags do not require a power source or transmitter, and only require a tag chip and antenna. They are cheaper, smaller, and easier to manufacture than active tags. Passive system ranges are limited by the power of the tag’s backscatter (the radio signal reflected from the tag back to the reader).

Passive tags can be packaged in many different ways depending on the specific RFID application requirements. They may be mounted on a substrate, or sandwiched between an adhesive layer and a paper label to create smart RFID labels. Passive tags may also be embedded in a variety of devices or packages to make the tag resistant to extreme temperatures or harsh chemicals.

A Battery-Assisted Passive (BAP or Semi-Passive) RFID tag is a type of passive tag which incorporates an integrated power source (usually a battery) to power on the chip so all the captured energy from the reader can be used for backscatter. Unlike transponders, BAP tags do not have their own transmitters.


### Tag Products and Manufacturers

| Manufacturer | Products/Models | Link | Notes |
| :------: | :------: | :-: | :------: |
| Alien | Squiggle Family (Squiggle, Short, Squiglette, Squig); Specialized Retail (Glint, HiScan, GT-Tag); High-Dielectric/Automotive (BAT-Tag, Wonder-Dog, G-Tag); Form-factor (SlimLine, 2x2, Square, SIT) |  | Higgs 4 and Higgs 3 Models / Inlays |
| Avery Dennison | Chips:Impinj, NXP, EM Microelectronic | https://rfid.averydennison.com/en/home/products-solutions.html | Inlays, Hard tags, Sustainable tags |
| Chronotrack, IPICO, J-Chip, My Laps, RFIDTiming | Bibs, chips, wristbands |  | Timing for Races |
| Confidex | Carrier, Windshield, Car Distribution, Casey, Silverline, Pino, Ironside, Halo, License Plate, Steelwave, Corona, Captura, Survivor | https://www.confidex.com/smart-industries/product-selector/ |  |
| Global Tag | Rugged Tags, Race Timing, In-Metal and On-Metal Tags, Wristbands, Spring Tag for Tires, Laundry Tags, Labels, Key fob, Token and Disc | https://www.global-tag.com/nfc-rfid-tags-ble-beacons/ | Italy |
| IC-Tag | Direct Thermal and Thermal-Transfer Labels, PolyPremium Labels, Capsules, IC-TAG, Wristbands, Inlays from Avery Dennison, Alien, UPM Raflatac |  |  |
| iDTRONIC | Waste Bin Tag UHF, Flex Tag UHF, RTI Label UHF, INDUS Tag UHF, In-Metal Tag UHF, On-Metal Tag UHF, In-Metal Tool Tag UHF, On-Metal Tool TagUHF, Hard Tag UHF, High-Temp. Tag UHF, Standard Label UHF, Wet/Dry Inlay UHF | https://idtronic-rfid.com/rfid-tags/ |  |
| IER | Inlays and Labels |  |  |
| InfoChip | NFC tags: DuraPlug (embedded), DuraZip (tag on a string), DuraTab (hand or screw on), DuraDisc (adhesive), DuraBand 2/Micro (for cylindrical objects) | https://www.infochip.com/products/ |  |
| Intermec |  |  |  |
| Invengo | UHF & NFC Inlays, Cards, Windshield Stickers, Metal Tags | https://channel.invengo.com/rfid-product-line/tags-inlays-comsumables/ |  |
| Laxcen | Alien and Impinj Inlays | http://www.laxcen.com/rfid.html | China |
| Metalcraft | Folded Tab, Hangable, Hard tags, Slim, Standard, Universal, Windshield, Destructible Windshield, Key fobs, Wristbands, NFC, Badges | http://www.idplate.com/category/rfid-tags-rfid-labels-and-asset-tags |  |
| Omni-ID | View Tags (tags with display screens), Power Tags (active tags), Prox Tags, IQ Tags, Fit Tags (embedded in tools and metal), Exo Tags (for harsh environments), Dura Tags (for harshest environments), Adept Tags (specialty use cases) | http://www.omni-id.com/products/ | China |
| RealSmart |  |  |  |
| RFID Canada | Cards, InLine, SlimFlex, Pino, InTag, Iron Tag, Ironside, Steewave, Halo, Survivor, Carrier, Captura, License Plate, Casey, SteelWING, Windshield, Inlays | http://www.rfidcanada.com/products/passive-hf/ultra-high-frequency-inlaystags-labels/ | All Confidex products? |
| SAG | Proximity Cards, RFID Key fob, RFID Tags, UHF Transponders, RFID Labels, Inlays, NFC Tags | http://www.sag.com.tw/index.php?_Page=products_first&SetLang=en-us | Large variety, China |
| Securakey | Cards with NXP, Impinj, Alien inlays | https://securakey.com/rfid/ |  |
| SkyRFID | ABS Hard tags, Medical Wrist Bands and Straps, Labels and Thin Flexible Tags, Pucks | http://skyrfid.com/RFID_Tags.php | Canada |
| SMARTRAC | Inlays and Labels, White Cards, Pre-laminates | http://www.smartrac-group.com/products-services.html |  |
| SONTEC | Hummingbird II, Albatross III, Pigeon I, Robin II, Eagle II |  |  |
| SYNOMETRIX | Wristbands, Seals, Flexible, Underground, U CODE | https://www.synometrix.com/ | China |
| UbiqueTag |  | http://en.ubiquetag.com/product.html | China |
| UPM RAFLATAC | Labels and Inlays | http://www.upmraflatac.com/na/en |  |
| Xerafy | Rugged Metal, Embeddable, on and off metal, metal skin labels, specialty | http://www.xerafy.com/en/products.html |  |
| Xtreme RFID | Rugged tags: Allied Series, Xtreme Tag series |  |  |


<div id="printers"/> 

## Printers

An RFID printer is a device used to write data to an RFID tag and also print any graphics, barcodes, and text onto the label as well. Choosing the right labels and inlays that are compatible with printers is crucial. The major companies that produce RFID printers and printing supplies are Zebra, Intermec, Datamax O’Neil, Toshiba, Printronix, Sato, and Avery Dennison.


<div id="distributors"/> 

## Distributors/Resellers

Many of the RFID products available on the market cannot be purchased directly from the manufacturer and have to be purchased from distributors and resellers. The following is a list of distributors and resellers in the US:
- Atlas RFID
- Berntsen
- BuyRFID
- Dynasys Technologies, Inc.
- Gao RFID
- International Coding Technologies (ICT)
- myRFIDspace
- RFIDTagSource


<div id="standards"/> 

## Standards

Different countries allocate different bands of the radio spectrum for RFID. The industry has worked to standardize the three main RF bands (LF, HF, and UHF). Most countries have assigned the 125 or 134 kHz areas of the spectrum for LF RFID systems and 13.56 MHz is generally used around the world for HF RFID systems. UHF RFID systems have only been around since the mid-1990s and countries have not agreed on a single area of the UHF spectrum for RFID. There are many non-RFID devices using the UHF spectrum so it is difficult for all governments to agree on a single UHF band for RFID.

Different countries have different bandwidth and power restrictions for UHF RFID systems. Across the European Union, UHF RFID ranges from 865 to 868 MHz with RFID readers able to transmit at maximum power (2 watts ERP) at the center of that bandwidth (865.6 to 867.6 MHz). In North America, the UHF RFID frequency ranges from 902 to 928 MHz with readers able to transmit at maximum power (1 watt ERP) for most of that bandwidth. Most other countries have either adopted the European Union or North America standard, or they are using a subset of one of the two bandwidths.

It is important to choose tags and readers that operate under the same standards and regions; otherwise, the reader and tags may not function. The following is a list of regions the ThingMagic Micro module supports: North America/FCC, European Union/ETSI EN 302 208, European Union/ETSI EN 300 220, European Union/ETSI Revised EN 302 208, Korea MIC, Korea KCC, China, India, Japan, Australia/AIDA LIPD Variation 2011, New Zealand.

### LF and HF Standards

Standards for LF animal-tracking systems are defined in ISO 14223 and ISO/IEC 18000-2. 

There are several HF RFID standards in place such as the ISO 15693 standard for tracking items, the ECMA-340 and ISO/IEC 18092 standards for Near Field Communication (NFC), and ISO/IEC 18000-3. Other HF standards include the ISO/IEC 14443A and ISO/IEC 14443 standards for MIFARE technology, which are used in smart cards and proximity cards, and the JIS X 6319-4 for FeliCa, which is a smart card system commonly used in electronic money cards. 

### UHF Standards

Standards are developed and issued by industry-specific, national, regional, and global bodies. International organizations that issue RFID-related standards include EPCglobal (a GS1 venture), the International Electrotechnical Commission (IEC), the International Standards Organization (ISO), and the Joint Technical Committee (JTC 1), a committee formed by ISO and IEC. Regional regulatory entities that govern the use of RFID include the Federal Communication Commission (FCC), which is in charge of the United States, the European Telecommunications Standards Institute (ETSI), which operates in Europe. 

Organizations that oversee RFID standards for specific industries include the Association of American Railroads (AAR), the Automotive Industry Standards Group (AIAG), the American Trucking Associations (ATA), and the International Air Transport Association (IATA). Additionally, the GS1 VICS Item Level RFID (VILRI) oversees standards around item-level tagging and the use of RFID technology throughout the retail supply chain.

Passive UHF RFID is currently the only type of RFID to be regulated by a single global standard. This standard is called EPCGlobal Gen 2 V1, or just UHF Gen 2. UHF Gen 2 defines the communications protocol for a passive backscatter, read-talks-first RFID system operating in the 860-960 MHz frequency range. EPCglobal certification testing includes conformance testing, which ensures that RFID products are compliant with the UHF Gen2 standard, and interoperability testing, which makes sure that all aspects of the tag reader interface are properly designed to interoperate seamlessly with other Gen 2 certified products. 

An update to the UHF Gen 2 standard called UHF Gen 2 V2 (Version 2) or just G2 was ratified in 2013. This new standard builds on the original V1 standard but ensures that future RFID communications have more complex and powerful security options to protect data and prevent tag counterfeiting. Under the G2 standard, the user is able to hide all, part, or none of the tag’s memory. Depending on what the reader’s access privileges are, and its proximity to the tag, the reader’s ability to access and/or modify tag data varies. 

The G2 standard also establishes an anticounterfeiting measure that involves cryptographically authenticating tags. UHF Gen2 V1 tags send static replies back to the reader, making it easy for cloners to create counterfeit tags. Under G2 standards, each time a reader sends a signal to a tag it sends a different secret number and the tag computes a reply specific to that interaction. In 2014 ISO will incorporate Gen2 V2 into the ISO/IEC 18000-63 standard.

Timeline:
- 1973: GS1’s bar code is the first single standard for product identification
- 2003: GS1 launches EPCglobal as a subsidiary organization to facilitate the technical development and adoption of EPC/RFID standards
- 2004: GS1 publishes the first-ever version of the EPC Gen2 air interface standard
- 2005: ISO/IEC incorporates the EPC Gen2 standard into ISO/IEC 18000-6C
- 2008: GS1 releases EPC Gen2 v1.2.0, featuring enhancements to improve RFID performance for item level tagging applications
- 2010: Industry working group launched to develop enhancements to the Gen2 standard for UHF, based on EPC user community requests for additional functionality
- 2013: Gen2v2 ratified – first major update since 2008
- 2014: ISO will incorporate Gen2v2 into the ISO/IEC 18000-63 standard

### Standards List

- ISO 14443: This high-frequency (HF) standard is designed to have a short read range and include encryption, since it was created for proximity cards. What that means is that it was created for secure payments. Identification cards -- Contactless integrated circuit cards -- Proximity cards.
- ISO 15693: This HF standard was developed for vicinity cards. It has no encryption and a longer read range than ISO 14443-based systems. It is used in many access-control systems, but has also been employed for inventory management and other applications.
- ISO 18000-3: This HF standard, developed for item management, has never really caught on. Most companies simply use ISO 15693 for item management.
- ISO 18000-6C: This ultrahigh-frequency (UHF) standard is based on the EPC Gen 2 air-interface protocol. Although there is an ISO 18000-6A and an ISO 18000-6B, it is ISO 18000-6C that is widely used for passive UHF systems. ISO 18000-6 was written to ensure that RFID chips and readers would be compatible but the standard does not address antennas.
- ISO 24730: This protocol governs the communication of active RFID transponders operating at 2.45 GHz, and is used in real-time location systems.
- Near Field Communication: While not an official ISO standard, NFC is based on ISO 14443 and adds some additional capabilities, such as the ability of a reader to emulate a tag. NFC will also incorporate ISO 15693 over time, so you will be able to use an NFC-enabled phone to enter a building.
- Wiegand: A common interface used to connect an RFID reader to an electronic entry system.
- IP65,68: The IP Code, International Protection Marking, sometimes misinterpreted as Ingress Protection Marking, classifies and rates the degree of protection provided against the intrusion (including body parts such as hands and fingers), dust, accidental contact, and water by mechanical casings and electrical enclosures. It is published by the International Electrotechnical Commission (IEC). 





<div id="protocol"/> 

## Protocol and Format

Most of the UHF tags on the market will be compliant with the UHF Gen 2 standard. Under this standard, a tag will have four types of memory: Reserved, EPC, TID, and User. The following are the memory definitions from the UHF Class 1 Gen 2 Version 2 Standard.

### Reserved Memory

“Reserved memory is optional. If a Tag does not implement kill and access passwords then the Tag need not physically implement Reserved memory. Because a Tag with non-implemented passwords operates as if it has zero-valued password(s) that are permanently read/write locked, these passwords must still be logically addressable in Reserved memory at the memory locations specified in 6.3.2.1.1.1 and 6.3.2.1.1.2.”

“6.3.2.1 Reserved memory shall contain the kill and/or access passwords, if passwords are implemented on the Tag. The kill password shall be stored at memory addresses 00 to 1F; the access password shall be stored at memory addresses 20 to 3F.”

“6.3.2.1.1.1 Kill password. The kill password is a 32-bit value stored in Reserved memory 00 to 1F, MSB first. The default (unprogrammed) value shall be zero. A Tag that does not implement a kill password shall behave as though it has a zero-valued kill password that is permanently read/write locked. A Tag shall not execute a password-based kill if its kill password is zero (see 6.3.2.12.3.4). An Interrogator may use a nonzero kill password in a password-based Kill-command sequence to kill a Tag and render it nonresponsive thereafter.”

“6.3.2.1.1.2 Access password. The access password is a 32-bit value stored in Reserved memory 20 to 3F, MSB first. The default (unprogrammed) value shall be zero. A Tag that does not implement an access password shall behave as though it has a zero-valued access password that is permanently read/write locked. A Tag with a zero-valued access password transitions from the acknowledged state to the secured state upon commencing access, without first entering the open state. A Tag with a nonzero-valued access password transitions from the acknowledged state to the open state upon commencing access; an Interrogator may then use the access password in an Access command sequence to transition the Tag from the open to the secured state.”

### EPC Memory

“EPC memory is required, but its size is Tag-manufacturer defined. The minimum size is 32 bits, to contain a 16-bit StoredCRC and a 16-bit StoredPC. EPC memory may be larger than 32 bits, to contain an EPC whose length may be 16 to 496 bits (if a Tag does not support XPC functionality) or to 464 bits (if a Tag supports XPC functionality), as well as an optional XPC word or words. See 6.3.2.1.2.”

“6.3.2.1 EPC memory shall contain a StoredCRC at memory addresses 00 to 0F, a StoredPC at addresses 10 to 1F, a code (such as an EPC, and hereafter referred to as an EPC) that identifies the object to which the Tag is or will be attached beginning at address 20, and if the Tag implements Extended Protocol Control (XPC) then either one or two XPC word(s) beginning at address 210.”

“The StoredCRC, StoredPC, EPC, and XPC word(s) shall be stored MSB first (i.e. the EPC’s MSB is at location 20).”

### TID Memory

“TID memory is required but its size is Tag-manufacturer defined. The minimum-size TID memory contains an 8-bit ISO/IEC 15963 allocation class identifier (either E0 or E2) in memory locations 00 to 07 as well as sufficient identifying information for an Interrogator to uniquely identify the custom commands and/or optional features that a Tag supports. TID memory may optionally contain other data. See 6.3.2.1.3.”

“6.3.2.1 TID memory shall contain an 8-bit ISO/IEC 15963 allocation class identifier at memory locations 00 to 07. TID memory shall contain sufficient identifying information above 07 for an Interrogator to uniquely identify the custom commands and/or optional features that a Tag supports.”

“If the class identifier is E0 then TID memory locations 08 to 0F contain an 8-bit manufacturer identifier, TID memory locations 10 to 3F contain a 48-bit Tag serial number (assigned by the Tag manufacturer), the composite 64-bit TID (i.e. TIDE memory 00 to 3F) is unique among all classes of Tags defined in ISO-IEC 15963, and TID memory is permalocked at the time of manufacture.”

“If the class identifier is E2 then TID memory above 07 shall be configured as follows:
- 08: XTID (X) indicator (whether a Tag implements an XTID)
- 09: Security (S) indicator (whether a Tag supports the Authenticate and/or Challenge commands)
- 0A: File (F) indicator (whether a Tag supports the FileOpen command)
- 0B to 13: a 9-bit Tag mask-designer identifier (obtainable from the registration authority)
- 14 to 1F: a Tag-manufacturer-defined 12-bit Tag model number
- Above 1F: As defined in the GS1 EPC Tag Data Standard

If the class identifier is E2 then TID memory locations 00 to 1F shall be permalocked at time of manufacture. If the Tag implements an XTID then the entire XTID shall also be permalocked at time of manufacture.”

### User Memory

“User memory is optional. A Tag may partition User memory into one or more files whose memory allocation may be static or dynamic. The Tag manufacturer chooses where a Tag stores its FileType and FileNum data. The Tag manufacturer also chooses the file-allocation block size (from one to 1024 words). User memory and the files in it may be encoded according to the GS1 EPC Tag Data Standard or to ISO/IEC 15961/15962. See 6.3.2.1.4, 6.3.2.1.4.1, 6.3.2.1.4.2, and 6.3.2.11.3.”

“6.3.2.1 User memory is optional. If a Tag implements User-memory then it may partition the User memory into one or more files. If the Tag implements a single file then that file is File_0.

A Tag may support User memory, configured as one or more files. User memory allows user data storage. If File_0 of User memory exists and has not yet been written then the 5 LSBs of the first byte (i.e. File_0 memory addresses 03 to 07) shall have the default value 00000.

The logical addressing of all memory banks and User-memory files shall being at 00. The physical memory map is Tag-manufacturer defined. When a Tag backscatters data from memory the order is left-to-right and bottom-to-top in Figure 6.19.”

### Lock/Unlock

“An Interrogator may issue a Lock command (see 6.3.2.12.3.5) to lock, permanently lock, unlock, or permanently unlock the kill password, access password, EPC memory bank, TID memory bank, or File_0 of User memory, thereby preventing or allowing subsequent changes (as appropriate). If the passwords are locked or permanently locked then they are unwriteable and unreadable by any command and usable only by a Kill or Access command. If EPC memory, TID memory, or File_0 are locked or permanently locked then they are unwriteable but readable, except for the L and U bits in EPC memory; an Interrogator with an asserted Untraceable privilege may alter the L and U bits regardless of the lock or permalock status of EPC memory (see 6.3.2.12.3.16).”

### Kill

All passive ultrahigh-frequency (UHF) RFID tags based on the Electronic Product Code (EPC) standard have a kill function. This function was incorporated into the standard due to security and privacy concerns when RFID was first released. A tag that has successfully been issued a kill command will no longer be able to respond to any command. Tags can be killed if they have a nonzero Kill password. If the password is unknown, or if a tag is a passive high-frequency (HF) or low-frequency (LF) tag, then the best way to deactivate it is to zap it with electricity.

### ThingMagic Micro Fields

The ThingMagic Micro reader will supply the following information when reading tags:
- EPC
- EPCString
- Time
- RSSI
- ReadCount
- RESERVEDMemData
- EPCMemData
- TIDMemData
- USERMemData
- Frequency
- Tag
- Reader
- Phase
- GPIO
- Data
- Antenna

**EPC** - The value of the EPC (excluding the StoredCRC and StoredPC).

**EPCString** - Returns the EPC value as a string.

**Time** - Contains the date and time of day the read occurred.

**RSSI** - The receive signal strength of the tag response in dBm. Most passive ultrahigh-frequency (UHF) readers employ RSSI, which stands for return signal strength indicator, and indicates the strength of the signal that the reader antenna receives from the tag. This helps to determine the tag's distance from the reader, and can be used to determine the direction in which a tag is moving or if a reader is closing in on a tag.

**ReadCount** - The number of times the tag was read on that antenna port. During a single read() operation tag de-duplication will occur on the reader but re-reads of the same tag will result in the ReadCount field being incremented. 

**RESERVEDMemData** - Does not contain data.

**EPCMemData** - Does not contain data.

**TIDMemData** - Does not contain data.

**USERMemData** - Does not contain data.

**Frequency** - The frequency in kHz the reader just completed using.

**Tag** - Contains the EPC Length (2 bytes), the PC Word (Protocol Control - 2 bytes), the EPC (usually 62 bytes), and the Tag CRC (2 bytes).

**Reader** - Returns null. Function unknown.

**Phase** - Average phase of tag response in degrees (0-180).

**GPIO** - The signal status (High or Low) of all GPIO pins when the tag was read.

**Data** - Contains Reserved, TID, EPC, or USER memory data depending on the filter criteria. Only one memory bank can be selected at a time.

**Antenna** - The antenna port number the tag was read on. If the same tag is read on more than one antenna there will be a tag buffer entry for each antenna on which the tag was read.


<div id="proxmark3"/> 

## Proxmark3

The Proxmark3 is a device that enables sniffing, reading, and cloning of RFID tags. It works against 13.56 MHz (HF) iClass and Mifare devices as well as 125 kHz (LF) Indala and HID/ProxCard. Refer to the Proxmark 3 Cheat Sheet listed in the references section for commands that fall into the following categories: generic, iClass, Mifare, Indala, HID/Proxmark, T55xx, data, and Lua scripts.

The Proxmark3 software is included in the FISSURE installer. The CLI can be launched from the _Tools>>RFID>>Proxmark3_ menu item. 

### Quick Replay

These are the steps for quickly recording and replaying RFID tags:

1. Hold the button down for 2 seconds.
2. Wait for dance to end and two solid red lights.
3. Put a card up to the antenna and see if the lights change. If so, the card is recorded.
4. Push the button to transmit the recording of the card.

### Common Commands 

The following are a list of frequently used commands for working with tags/cards:

```
hw tune
hw version

lf search
hf search
lf em 4x05info
lf em 4x05dump
lf em 4x05readword <address> <password>
lf em 4x05writeword a <address> p <password> d <data> (s-swap the data bit order, i-invert the data bits)

lf read
data plot (click on it and press 'h' for plot-specific options, up/down to zoom)
lf rawdemod fs
data print x
lf sim
```

### Raw Data 

The following commands are for working with raw data:

```
lf config H (for 134 kHz)
lf read <samples>
data hpf (removes DC offset)
data ltrim <samples>
data rtrim <samples>
data norm
data save <../filename>
data load <../filename>
lf sim
lf simpsk h
```

The Proxmark3 client has built-in tools for detecting clock rates, demodulating FSK/ASK/PSK data, and protocol libraries for a couple LF/HF RFID card models. The sim commands do not work as well for PSK signals as it does for FSK/ASK. When simulating, the client will automatically try to demodulate a captured signal into bits and then modulate the bits. It has difficulty demodulating signals for all but a few possible clock rates. There is also the option of inputting a bitstream manually. There does not appear to be an analog option to replay the raw signal.

### Cloning HID/ProxCard Cards

These are the steps to clone a HID/ProxCard cards:

1. Verify the original card with `lf hid read`
2. Test the value with `lf hid sim 200670012d`
3. Read new T55xx card with `lf t55xx detect`
4. Clone to new T55xx card with `lf hid clone 200670012d`
5. Verify new T55xx card with `lf t55xx detect` and `lf hid read`


<div id="zepassd"/> 

## ZEPASSD

The ZEPASSD E-Z Pass Capture Agent is a software-defined radio (SDR) agent for capturing nearby E-Z Pass metadata. It is included with the FISSURE installer and can be run by accessing the _Tools>>RFID>>ZEPASSD: E-Z Pass Capture Agent_ menu item. It is configured by default for a USRP B210/B205mini. 

```
Usage: ./zepassd {options} [output filename]
Options:
  -h [ --help ]                    Get some help (this screen)
  -d [ --device ] arg              USRP device ID to use
  -c [ --center ] arg (=915750000) Center frequency
  -T [ --tx-gain ] arg (=75)       Transmit gain
  -t [ --tx-port ] arg (=A:A)      Transmit port on USRP
  -A [ --tx-ant ] arg (=TX/RX)     Transmit antenna on specified USRP TX port
  -R [ --rx-gain ] arg (=75)       Receive gain
  -r [ --rx-port ] arg (=A:A)      Receive port on USRP
  -a [ --rx-ant ] arg (=RX2)       Receive antenna on the specified USRP RX 
                                   port
  -P [ --pulse-len ] arg (=20)     Length of activation pulse, in microseconds
  --gps-pps                        Use the GPS PPS source and synchronize local
                                   time
  -p [ --pulse-spacing ] arg (=25) Pulse interval, in milliseconds
  -m [ --max-age ] arg (=30)       Maximum stale pass age, in seconds
```

```
./zepassd --tx-port A:A --rx-port A:A --tx-gain 87 --rx-gain 85 -p 20 foobar
./zepassd --device "serial=F00FC7C8" --tx-port "A:A" --rx-port "A:A" --tx-gain 87 --rx-gain 85 -p 20 foobar 
```

```
{"passHeader":7, "tagType":0, "appId":1, "groupId":65, "agencyId":4, "serialNum":#######, "lastSeenAt":6602106, "nrSamples":17, "centerFreqDelta":-837891, "seenAt": "2021-11-26 01:05:00"}
```









