# FISSURE - The RF Framework 

<img src="/docs/Icons/README/logo.png">

**Frequency Independent SDR-based Signal Understanding and Reverse Engineering**

## Overview Videos

<table>
  <tr>
    <td align="center">
      <a href="https://youtu.be/vUJakWBVnwY">
        <img src="https://img.youtube.com/vi/vUJakWBVnwY/hqdefault.jpg" width="360">
      </a>
      <br>
      <sub>FISSURE Operational Overview</sub>
    </td>
    <td align="center">
      <a href="https://youtu.be/Xgc8u7hLBfk">
        <img src="https://img.youtube.com/vi/Xgc8u7hLBfk/hqdefault.jpg" width="360">
      </a>
      <br>
      <sub>FISSURE Overview (Slides)</sub>
    </td>
  </tr>
</table>


## Introduction

FISSURE is an **open-source RF framework** that supports both **operational deployments** and **research and education**.
- For **operators**, it provides a rapidly deployable toolkit for signal detection, classification, protocol discovery, fuzzing, vulnerability analysis, and real-time integration with TAK.
- For **educators and researchers**, it lowers the barrier to entry for SDR and reverse engineering, offering a shared environment for learning, experimentation, and publishing new methods.

FISSURE streamlines complex SDR workflows by centralizing software, libraries, and reference material into one consistent framework that runs on desktops, laptops, single-board computers, and ruggedized systems, or scales to distributed tactical nodes networked in the field.

<p align="center">
<img src="/docs/Icons/README/ecosystem.png" width="640" height="325">
</p>

## Key Capabilities

- Detect, classify, and analyze RF signals
- Collect, replay, and manipulate IQ data
- Discover protocols and craft custom packets
- Execute fuzzing and vulnerability testing
- Archive signals and build playlists for testing
- Coordinate distributed sensor nodes
- Geolocate RF emitters and targets
- Integrate alerts, targets, and artifacts into TAK
- Automate workflows with AI and ML integration

<p align="center">
  <img src="/docs/Icons/README/rf_re.png" height="275">&nbsp;&nbsp;&nbsp;&nbsp;
  <img src="/docs/Icons/README/key_capabilities1.png" height="275">
</p>

## FISSURE and Fracture

Fracture is AIS's deployable tactical RF system built on the open-source FISSURE framework.

FISSURE provides the underlying software environment for RF sensing, signal analysis, protocol experimentation, TAK integration, distributed node coordination, and plugin-based capability development. Fracture extends this foundation into deployable hardware configurations designed for operational use.

Fracture focuses on distributed RF sensing, geolocation, RF effects, electronic warfare workflows, and real-time operator control through WinTAK and ATAK. A central hub coordinates edge nodes over IP networks and long-range RF links to support sensing, targeting, and mission execution across distributed environments.

The architecture is designed to support fixed-site, vehicle, manpack, sUAS, and fixed-wing deployments while remaining extensible through FISSURE's plugin framework.

For organizations requiring a supported and integrated tactical RF capability, Fracture provides a productization path that preserves the flexibility, transparency, and extensibility of the underlying FISSURE ecosystem.

<p align="center">
<img src="/docs/Icons/README/fracture_ov1.png" style="width: 75%; height: auto;">
</p>

### Fracture System Architecture

<p align="center">
<img src="/docs/Icons/README/fracture_system_architecture.png" style="width: 75%; height: auto;">
</p>

### TAK Integration Workflow

<p align="center">
<img src="/docs/Icons/README/fracture_workflow.png" style="width: 40%; height: auto;">
</p>

## Deployment Options

- Desktop GUI for visualization and prototyping
- Headless nodes for remote sensing and autonomous operations
- Containerized services for scalable and repeatable installs
- TAK integration for mission relevance and shared situational awareness

---

<p align="center">
<img src="/docs/Icons/README/fissure_deployments_cropped.jpg" style="max-width: 858px; width: 100%; height: auto;">
</p>

---

<p align="center">
<img src="/docs/Icons/README/system_overview.png" style="width: 75%; height: auto;">
</p>

## Dual-Use Relevance

- **Operators:** Detect, geolocate, and respond to RF activity in the field
- **Researchers:** Test new algorithms, automation, and AI and ML approaches
- **Educators:** Teach SDR, DSP, RF security, real-time processing, and reverse engineering in the classroom
- **Students and Hobbyists:** Explore SDR workflows and learn about technology without steep setup overhead

## Roadmap and Development

FISSURE’s roadmap evolves with customer demand and community feedback.

For the most up-to-date view, explore the interactive roadmap (updated every July):

- [View Interactive Roadmap](https://ainfosec.github.io/FISSURE/Roadmap/)  

### Current Priorities

- **Plugin Ecosystem & Actions:** Applying the new plugin and action architecture throughout the FISSURE Dashboard, WinTAK, ATAK, and sensor nodes. Expanding plugin support, converting existing library content into plugins, and simplifying capability deployment while protecting sensitive functionality through the plugin framework.
- **TAK Integration & Operator Workflows:** Expanding WinTAK and ATAK functionality, improving target management, geolocation workflows, alerting, artifact handling, and operator-driven actions. Focus areas include real-world testing, performance optimization, usability improvements, and tighter integration between TAK and distributed sensor nodes.
- **Installer, Packaging & Deployment:** Improving installer reliability, refining Apptainer support, hosting downloadable container images, delivering prebuilt deployment options, and simplifying installation across supported operating systems and hardware platforms.
- **Tactical Nodes, Sensors & Networking:** Expanding support for tactical node deployments, integrating additional sensors and hardware, evaluating new communications pathways including cellular, Starlink, mesh networking, and communications radios, and improving resilience across distributed deployments.
- **Geolocation, Direction Finding & Electronic Support:** Advancing geolocation, direction-finding, and monitoring capabilities through field testing and operational evaluations. Emphasis is placed on practical electronic support workflows, multi-node sensing, performance validation, and the collection of real-world operational feedback.

## Videos

- [FISSURE Videos](https://www.youtube.com/playlist?list=PLs4a-ctXntfjpmc_hrvI0ngj4ZOe_5xm_)
- [AIS YouTube](https://www.youtube.com/@assuredinformationsecurity/featured)

## White Papers

FISSURE is supported by a series of white papers that explore both technical and operational applications across different domains.

1. [FISSURE Overview](/docs/White_Papers/FISSURE_Overview.pdf)
2. [FISSURE for Counter-UAS](/docs/White_Papers/FISSURE_CUAS.pdf)
3. [FISSURE for UAS Payloads & Aerial Operations](/docs/White_Papers/FISSURE_UAS_Payload_Aerial_Ops.pdf)
4. [FISSURE for Maritime](/docs/White_Papers/FISSURE_Maritime.pdf)
5. [FISSURE for Vehicle & Mobility Systems](/docs/White_Papers/FISSURE_Vehicle_Mobility_Systems.pdf)
6. [FISSURE for Perimeter & Infrastructure Defense](/docs/White_Papers/FISSURE_Perimeter_Infrastructure_Defense.pdf)
7. [FISSURE for TAK & Mobile](/docs/White_Papers/FISSURE_TAK_Mobile_Integration.pdf)
8. [FISSURE for Training & Education](/docs/White_Papers/FISSURE_Training_Education.pdf)
9. [FISSURE Technical Details & Architecture](/docs/White_Papers/FISSURE_Technical_Details_Architecture.pdf)

## Blog Posts

AIS has published several articles highlighting FISSURE’s applications, updates, and use cases:
- [Demonstrating FISSURE as a Drone Payload at Northern Strike 2025](https://www.ainfosec.com/fissure-demo-at-northern-strike)
- [A Recap of My DEF CON 2024 Presentation on FISSURE Updates](https://www.ainfosec.com/a-recap-of-my-def-con-2024-presentation-on-fissure-updates)
- [FISSURE: Navigating the Open-Source Realm](https://www.ainfosec.com/fissure-navigating-the-open-source-realm)
- [FISSURE: The RF Framework for Everyone](https://www.ainfosec.com/fissure-the-rf-framework-for-everyone)

[See all AIS blog posts](https://www.ainfosec.com/blog/)

## News

![NEW](https://img.shields.io/badge/NEW-Feature-brightgreen) 

**Plugin & Action Architecture:** FISSURE is transitioning to a unified plugin and action framework that enables capabilities to be packaged, deployed, and executed across the Dashboard, sensor nodes, WinTAK, and ATAK.

![NEW](https://img.shields.io/badge/NEW-Feature-brightgreen) 

**WinTAK Integration:** WinTAK now supports node management, alerts, targets, detections, artifacts, plugin selection, action execution, and distributed sensor node operations.

![NEW](https://img.shields.io/badge/NEW-Feature-brightgreen) 

**ATAK Integration:** ATAK integration is actively under development, extending FISSURE and Fracture capabilities to mobile devices and tactical edge operators.

![NEW](https://img.shields.io/badge/NEW-Feature-brightgreen) 

**Distributed Tactical Nodes:** Sensor nodes support remote operation, distributed sensing workflows, TAK integration, artifact collection, alerting, and plugin execution across IP-connected networks.

![NEW](https://img.shields.io/badge/NEW-Feature-brightgreen) 

**Geolocation & Target Management:** Development efforts continue on RF geolocation, target management, multi-node coordination, and real-world operational testing.

![NEW](https://img.shields.io/badge/NEW-Feature-brightgreen) 

**Apptainer Containerization:** FISSURE can be deployed within Apptainer containers to simplify installation, testing, portability, and deployment across supported platforms.

![NEW](https://img.shields.io/badge/NEW-Documentation-brightgreen) 

**Fracture Architecture & TAK Workflows:** New diagrams and documentation have been added to illustrate Fracture system architecture, TAK integration workflows, and distributed tactical operations.

## Upcoming/Recent Events

![Exhibition](https://img.shields.io/badge/Event-Exhibition-darkgray) **May 5-8, 2025**: SOF Week - Assured Information Security, Inc. (AIS) booth

![Career Fair](https://img.shields.io/badge/Event-Career%20Fair-darkgray) **Thu. February 6, 2025**: Binghamton University Spring 2025 Job and Internship Fair - 1100-1500 EST

![CTF](https://img.shields.io/badge/Event-CTF-purple) **January 20, 2025 (Runs Indefinitely)**: FISSURE Challenge. [Link](https://fissure.ainfosec.com/) (Now Live)

![Conference](https://img.shields.io/badge/Event-Conference-darkgray) **Tue. September 17, 2024**: GNU Radio Conference 2024 - 1605-1635 EST [Description/Slides](https://events.gnuradio.org/event/24/contributions/649/), [Live Recording](https://youtu.be/5UYhUi8SiK4?t=27282)

![Career Fair](https://img.shields.io/badge/Event-Career%20Fair-darkgray) **Thu. September 5, 2024**: Binghamton University STEM Job and Internship Fair - 1100-1530 EST

![Conference](https://img.shields.io/badge/Event-Conference-darkgray) **Sat. August 10, 2024**: DEF CON 32 - RF Village - 1400-1500 PST. [Prerecorded Video](https://www.youtube.com/watch?v=5nYiVR-PsOc), [Live Recording](https://www.youtube.com/watch?app=desktop&v=mhbJHOGrCik)

## Documentation

<p align='center'>
<a target="_blank" href="https://fissure.readthedocs.io/en/latest/">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="/docs/Icons/README/documentation_user_manual.png" width=110px, height=110px>
  <source media="(prefers-color-scheme: light)" srcset="/docs/Icons/README/documentation_user_manual.png" width=110px, height=110px>
  <img alt="User Manual" src="">
</picture>
</a>
<a target="_blank" href="https://fissure.readthedocs.io/en/latest/pages/installation.html">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="/docs/Icons/README/documentation_installation.png" width=110px, height=110px>
  <source media="(prefers-color-scheme: light)" srcset="/docs/Icons/README/documentation_installation.png" width=110px, height=110px>
  <img alt="Installation" src="">
</picture>
</a>
<a target="_blank" href="https://fissure.readthedocs.io/en/latest/pages/hardware.html">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="/docs/Icons/README/documentation_hardware.png" width=110px, height=110px>
  <source media="(prefers-color-scheme: light)" srcset="/docs/Icons/README/documentation_hardware.png" width=110px, height=110px>
  <img alt="Hardware" src="">
</picture>
</a>
<a target="_blank" href="https://fissure.readthedocs.io/en/latest/pages/components.html">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="/docs/Icons/README/documentation_components.png" width=110px, height=110px>
  <source media="(prefers-color-scheme: light)" srcset="/docs/Icons/README/documentation_components.png" width=110px, height=110px>
  <img alt="Components" src="">
</picture>
</a>
<a target="_blank" href="https://fissure.readthedocs.io/en/latest/pages/operation.html">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="/docs/Icons/README/documentation_operation.png" width=110px, height=110px>
  <source media="(prefers-color-scheme: light)" srcset="/docs/Icons/README/documentation_operation.png" width=110px, height=110px>
  <img alt="Operation" src="">
</picture>
</a>
<a target="_blank" href="https://fissure.readthedocs.io/en/latest/pages/development.html">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="/docs/Icons/README/documentation_development.png" width=110px, height=110px>
  <source media="(prefers-color-scheme: light)" srcset="/docs/Icons/README/documentation_development.png" width=110px, height=110px>
  <img alt="Development" src="">
</picture>
<a target="_blank" href="https://fissure.readthedocs.io/en/latest/pages/about.html">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="/docs/Icons/README/documentation_credits.png" width=110px, height=110px>
  <source media="(prefers-color-scheme: light)" srcset="/docs/Icons/README/documentation_credits.png" width=110px, height=110px>
  <img alt="Credits" src="">
</picture>
</a>
</p>

- [Info Sheet](https://www.ainfosec.com/wp-content/uploads/2023/04/AIS-FISSURE.pdf)
- [AIS Page](https://www.ainfosec.com/technologies/fissure/)
- [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE_Poore_GRCon22.pdf)
- [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Capabilities

- [FISSURE Capabilities (Updated: 11Sep24)](https://docs.google.com/viewer?url=https://raw.githubusercontent.com/ainfosec/FISSURE/Python3/docs/Help/FISSURE_Capabilities.pdf)

<table style="padding:10px">
  <tr>
    <td><img src="/docs/Icons/README/detector.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Signal Detector</b></i></small></dt></td>
    <td><img src="/docs/Icons/README/iq.png" align="center" width="200" height="165"><dt align="center"><small><i><b>IQ Manipulation</b></i></small></dt></td>
    <td><img src="/docs/Icons/README/library.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Signal Lookup</b></i></small></dt></td>
    <td><img src="/docs/Icons/README/pd.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Pattern Recognition</b></i></small></dt></td>
  </tr>
  <tr>
    <td><img src="/docs/Icons/README/attack.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Attacks</b></i></small></dt></td>
    <td><img src="/docs/Icons/README/fuzzing.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Fuzzing</b></i></small></dt></td>
    <td><img src="/docs/Icons/README/signal_playlists.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Signal Playlists</b></i></small></dt></td>
    <td><img src="/docs/Icons/README/gallery.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Image Gallery</b></i></small></dt></td>
  </tr>
  <tr>
    <td><img src="/docs/Icons/README/packet.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Packet Crafting</b></i></small></dt></td>
    <td><img src="/docs/Icons/README/scapy.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Scapy Integration</b></i></small></dt></td>
    <td><img src="/docs/Icons/README/crc_calculator.png" align="center" width="200" height="165"><dt align="center"><small><i><b>CRC Calculator</b></i></small></dt></td>
    <td><img src="/docs/Icons/README/log.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Logging</b></i></small></dt></td>
  </tr>  
  <tr>
    <td><img src="/docs/Icons/README/dataset_builder.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Dataset Builder</b></i></small></dt></td>
    <td><img src="/docs/Icons/README/online_archive.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Online Archive</b></i></small></dt></td>
    <td><img src="/docs/Icons/README/third-party_tools.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Third-Party Tools</b></i></small></dt></td>
    <td><img src="/docs/Icons/README/dark_mode.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Dark and Custom Themes</b></i></small></dt></td>
  </tr>  
</table>

## Hardware

The following is a list of "supported" hardware with varying levels of integration:
- USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
- HackRF
- RTL2832U
- 802.11 Adapters
- LimeSDR
- bladeRF, bladeRF 2.0 micro
- Open Sniffer
- PlutoSDR
- SDRplay: RSPduo, RSPdx, RSPdx R2

## Getting Started

**Supported**

There are now two branches within FISSURE: the Python3 branch and the Python2_maint-3.7 branch. The Python3 branch contains the latest code and has support for PyQt5 and GNU Radio versions 3.8 and 3.10. The Python2_maint-3.7 branch has been deprecated and will only be updated if specific third-party tools require GNU Radio version 3.7 or an older operating system. Only the latest minor versions of operating systems will be supported for installs and we will do our best to keep up. Operating systems that have been updated and yet to be fully tested will be listed under "In-Progress."

The GitHub releases provided in this repository are periodic snapshots of the project's state, intended primarily for archival purposes. These releases may not include the latest updates, bug fixes, or features currently under development. To access the most up-to-date version of the software, we strongly recommend using the main Python3 branch, which reflects ongoing development and the current state of the project.

FISSURE is most extensively tested on Ubuntu, making it the most validated platform.

Operating System | FISSURE Branch | Default GNU Radio Version
:-------------------------:|:-------------------------:|:-------------------------:
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM (Orange Pi) / Ubuntu for Raspberry Pi | Python3 | maint-3.10 |
| Windows 11 WSL2 | See Supported Linux Version | See Supported Linux Version |

**In-Progress (beta)**

These operating systems are still in beta status. They are under development and several features are known to be missing. Items in the installer might conflict with existing programs or fail to install until the status is removed.

Operating System | FISSURE Branch | Default GNU Radio Version
:-------------------------:|:-------------------------:|:-------------------------:
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Note: Certain software tools do not work for every OS. Refer to [Known Conflicts and Third-Party Software](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts)


**Apptainer Installs**

Testing is underway with apptainer to containerize FISSURE installs. Combinations of host OS, container OS, and FISSURE install mode (full, base, Dashboard, HIPRFISR, SensorNode) are still in progress. The following are supported combinations.

Host Operating System | Container Operating System | FISSURE Mode
:-------------------------:|:-------------------------:|:-------------------------:
| Ubuntu 24.04 | Ubuntu 24.04 | full |

**Installation** 

For adding SSH keys to GitHub and cloning with SSH (needed for contributing):
```
ssh-keygen -t ed25519
cat ~/.ssh/id_ed25519.pub
Paste text into "Settings" > "SSH and GPG keys" > "New SSH Key"
git clone git@github.com:ainfosec/FISSURE.git 
```

For cloning with https:
```
git clone https://github.com/ainfosec/FISSURE.git
```

Preparing the installer:
```
cd FISSURE
git checkout Python3  # Optional, or Python2_maint-3.7 for select legacy third-party tools
./install
```

Notes:
- The installer will ask to install PyQt software dependencies required to launch the installation GUIs if they are not found. 
- Select the operating option in the GUI that best matches your operating system (should be detected automatically if your OS matches an option).
- Periodically answer prompts regarding third-party software throughout the install. Use your best judgment, the answers will not likely impact FISSURE.
- Ensure your system clock is set correctly to avoid errors with apt rejecting repository updates.
- After installation, reboot your computer or log out and back in so that user group changes take effect.

<p align="center">
<img src="/docs/Icons/README/install1.png" width="257" height="379">
</p>

It is recommended to install FISSURE on a clean operating system to avoid conflicts with existing software. Further efforts towards virtualization and dependency management will be continued. Notes on the installer:
- The items listed under the "Minimum Install" category are what is required to launch the FISSURE Dashboard without errors. 
- The radio hardware and out of tree modules are required to perform many actions in FISSURE.
- The flow graphs need to be recompiled to avoid errors across GNU Radio minor versions.
- Software programs outside the minimum install are optional and can be installed as needed. 
- Select all the recommended checkboxes (Default button) to avoid errors while operating the various tools within FISSURE. 
- Items unchecked by default may not install properly or could possibly conflict with existing programs (please suggest fixes!). 
- There will be multiple prompts throughout the installation, mostly asking for elevated permissions and user names. These prompts are primarily tied to third-party tools, refer to installation instructions provided by the maintainer for details.
- If an item contains a "Verify" section at the end, the installer will run the command that follows and highlight the checkbox item green or red depending on if any errors are produced by the command. Checked items without a "Verify" section will remain black following the installation.
- To avoid installation and permission errors, download FISSURE to a user owned directory such as Home. Run the install script and the fissure command without using sudo. Many of the third-party tools will be downloaded to and installed from the `~/Installed_by_FISSURE` directory.

<p align="center">
<img src="/docs/Icons/README/install2.png" width="692" height="479">
</p>

The FISSURE installer is helpful for staging computers or installing select software programs of interest. The code can be quickly modified to allow for custom software installs. The size estimates for the programs are before and after readings from a full install. The sizes for each program are not exact as some dependencies are installed in previously checked items. The sizes may also change over time as programs get updated.

<p align="center">
<img src="/docs/Icons/README/install3.png" width="692" height="479">
</p>

**Remote Sensor Node Installation**

Install FISSURE per usual on a general purpose computer. Install FISSURE on the remote computer in the same directory location as the local computer (until further notice) to avoid filepath errors with certain actions. To configure the sensor node for remote operation, edit the "default.yaml" file in the `./YAML/Sensor_Node_Config/` directory and edit the following fields:
- nickname: (anything but "Local Sensor Node")
- hiprfisr_ip_address: (the HIPRFISR/hub IP address the sensor node connects to)
- hardware: (fill with your hardware specifics) 

Change the "autorun" field from from `false` to `true` to run the default autorun playlist file on startup and forgo remote operations. New autorun playlists can be generated and saved from the Dashboard Autorun tab.

An IP remote sensor node connects to HIPRFISR as a CURVE client. It needs the matching `certificates/clients/client_0.key_secret` and `certificates/server/server.key` files. Keep the private key out of source control and readable only by the sensor-node service account.

**Apptainer Remote Sensor Node Deployment**

The dedicated Apptainer deployment packages the headless `SensorNode` install, transfers it with SCP over AsyncSSH, installs it as a systemd service, and verifies both process health and a fresh heartbeat from HIPRFISR. Runtime configuration, certificates, logs, node UUID, and the writable overlay remain outside the SIF so upgrades preserve node identity and do not bake keys into the image.

Prerequisites:

- Apptainer on the build computer (or pass an existing SIF with `--image`).
- Python 3.10 or newer with the deployer's AsyncSSH and docopt dependencies.
- SSH access to the remote node and `sudo` permission for installing/managing
  its system service.
- The current FISSURE installation's Sensor Node YAML, already configured with
  the desired remote nickname and HIPRFISR address.
- Installed certificates containing `clients/client_0.key_secret` and
  `server/server.key`.

Install the Python deployment dependencies:

```
python3 -m pip install -r Installer/requirements-node-deploy.txt
```

For the basic installation, provide only the remote IP. The deployer assumes
the `root` SSH account and securely prompts for its password:

```
Installer/deploy_remote_sensor_node.py 192.0.2.20
```

The deployer uses `YAML/Sensor_Node_Config/default.yaml` exactly as installed
and selects the installed
`certificates/clients/client_0.key_secret` and
`certificates/server/server.key`. It performs no address discovery and does not
modify the installed YAML or certificates.

Before opening SSH, a full deployment uses the existing
`build/fissure-sensor-node.sif` or builds it locally when it does not exist.
Pass `--image /path/to/image.sif` to select a different existing image.
If the local Apptainer executable is also missing, the deployer first installs
it from the official PPA and then builds the SIF. Local `sudo` may prompt in
the terminal during this step.

If Apptainer is missing remotely, a full deployment installs it from the
official Apptainer PPA on Ubuntu-derived `amd64` or `arm64` systems. This
requires remote internet access and adds the PPA before installing the
`apptainer` package. Use `--no-install-apptainer` to disable local and remote
package changes;
unsupported systems fail with a manual-install message. A `--health-only`
check never installs packages.

Add `-i ~/.ssh/sensor-node` to use a private key instead of a password. Use an
explicit `user@host`, `--config`, or `--certificates` to override the basic
defaults. To deploy an existing image, add
`--image /path/to/fissure-sensor-node.sif`.

When connecting as a non-root user, the deployer first tries passwordless
`sudo`. If it is unavailable, it securely prompts once for the sudo password,
validates it, and reuses it for privileged package, installation, health, and
rollback commands. The password is sent only over SSH standard input; it is
not placed in command arguments or remote files. Direct root SSH does not
invoke `sudo`.

To check a running deployment again without changing it:

```
Installer/deploy_remote_sensor_node.py 192.0.2.20 --health-only
```

To stop the remote service and remove its SIF, configuration, certificates,
logs, overlay, and persistent state:

```
Installer/deploy_remote_sensor_node.py 192.0.2.20 --uninstall
```

Uninstall uses the same SSH key/password and sudo handling as deployment. It
does not remove the remote Apptainer package or the local
`build/fissure-sensor-node.sif`, so running the basic installation command
again reuses the existing local image.

Use `-i`/`--identity` to select a private key explicitly. If it is omitted, the deployer securely prompts once for the SSH password and reuses it if deployment requires a second connection. AsyncSSH continues to apply normal OpenSSH configuration and known-hosts checks. The default health check waits for a fresh HIPRFISR heartbeat and rolls back a failed upgrade. Use `--startup-only` only when intentionally staging a node without a reachable hub. Run the script with `--help` for paths, overlay sizing, and other deployment settings.

**Local Dashboard Usage**

Open a new terminal after installation and enter:

```
fissure
```

The intended method for launching the FISSURE Dashboard is through the terminal without sudo. The terminal provides important status and feedback for some operations. Refer to the FISSURE documentation for more details. 

A local sensor node can be launched through the top buttons in the FISSURE Dashboard and helps maintain all pre-existing FISSURE functionality on a standalone workstation. Only one local and four remote sensor nodes (or five remote) are supported at this time. 

If any of the programs freeze or hang on close, the following commands can be used to detect a problem or forcibly shut down:
```
sudo ps -aux | grep fissure
sudo pkill python3
sudo kill -9 <PID of __main__.py>
sudo pkill python3 && sudo pkill -9 -f fissure
```

**Headless Hub**

The HIPRFISR can be launched without the Dashboard GUI to make TAK testing and operational deployments more efficient. Open a new terminal after installation and enter:

```
fissure-hiprfisr
```

The hub will automatically connect up to the TAK server and remote nodes will be able to join without interaction. 

**Remote Sensor Node Usage**

After configuring the sensor node config file (see above), the sensor node code can be run using this command in a terminal:

```
fissure-sensor-node
```

The sensor node code will stay active until ctrl+c is applied. Connecting to the remote sensor node is performed through the top buttons of the FISSURE Dashboard. Right-clicking the top buttons will select an active sensor node to perform operations. Future operations that utilize more than one node at a time will be handled on a case-by-case basis within the individual tabs.

**Windows 11 WSL2 Instructions**

FISSURE can run in Windows 11 using WSL2 for supported Linux operating systems. The following are instructions to help install WSL2, install a Linux operating system, set up USB passthrough, and install FISSURE in the Linux operating system.

Install WSL2:

1. Open PowerShell as Administrator
2. `wsl --install`
3. Enable Virtualization in BIOS, check using: Task Manager>Performance>CPU>Virtualization
4. `wsl --set-default-version 2`
5. `wsl --list --online`
6. Install a specific version (plain Ubuntu should be the latest version listed): `wsl --install -d Ubuntu-22.04`
7. Open the Start Menu, search for Ubuntu and launch it
8. To uninstall a distribution: `wsl --unregister Ubuntu-22.04`

Enable USB passthrough in a PowerShell as Administrator:

1. `winget install usbipd`
2. Add usbipd to System PATH: Start Menu>Environment Variables>Edit the system environment variables>System Properties>Environment Variables>System Variables>Path>Edit>New: `C:\Program Files\usbipd-win`
3. Close and reopen PowerShell as Administrator
4. `usbipd wsl list`
5. `usbipd wsl attach --busid <BUS_ID>` or `usbipd wsl attach --busid <BUS_ID> --wsl <DistributionName>` (replace <BUS_ID> with the actual BUS ID of the device)
6. To detach: `usbipd wsl detach --busid <BUS_ID>`

Install FISSURE in Linux Terminal:

1. `sudo apt-get install git`
2. Clone FISSURE and install as detailed above

**TAK Setup**

To install and run a local TAK server:

1. Register and download the TAK server docker zip from the website: https://tak.gov/products/tak-server
2. Create the `~/Installed_by_FISSURE` directory if it does not exist
3. Place the downloaded .zip file in `~/Installed_by_FISSURE`
4. Run the TAK Server item in the FISSURE installer
5. For local WebTAK, load the `~/Installed_by_FISSURE/taskerver-docker-#.#-RELEASE-##/tak/certs/files/webadmin.p12` file into your browser (settings>certificates)
6. Set "tak_on_startup" field to True in `/FISSURE/YAML/User Configs/default.yaml` or select "Start Docker Containers" from the FISSURE Dashboard TAK menu
7. Open WebTAK from FISSURE TAK menu and verify map loads with internet connection
8. Set "connect_mode" (auto/manual/disabled) field in `/FISSURE/YAML/User Configs/default.yaml`. Connect to TAK server in FISSURE Dashboard TAK menu if set to manual.
9. Run a FISSURE effect that creates a TAK alert (examples coming soon)

To connect to a remote TAK server:

1. Update the certificate filepaths in `/FISSURE/YAML/User Configs/default.yaml`
2. Set "connect_mode" (auto/manual/disabled) field in `/FISSURE/YAML/User Configs/default.yaml`. Connect to TAK server in FISSURE Dashboard TAK menu if set to manual.
3. Run a FISSURE effect that creates a TAK alert (examples coming soon)

**Apptainer Setup**

Apptainer is used to containerize most of the FISSURE installation, making deployment and testing simpler across different systems. While the majority of FISSURE runs inside the Apptainer environment, several components still require setup on the **host**:

- **Docker containers** (such as the PostgreSQL database and TAK Server) run on the **host**, not inside Apptainer.  
- **udev rules, USB drivers, and hardware interfaces** must also be installed on the host for SDRs, Wi-Fi adapters, and other peripherals to function properly.

Pre-built Apptainer containers and ISO images are planned for future releases to simplify setup. These instructions are intended for users who want to **build the Apptainer container from source** or customize their installation.

1. **Clone the FISSURE Repository**

2. **Configure the Installer**
   - Open `FISSURE/install_apptainer.sh` in a text editor.  
   - Review and adjust the variables near the top of the script.  
     Set each option (`true` / `false`) according to what you want to include (e.g., `UHD`, `HackRF`, `Wi-Fi`, etc.).  
   - Choose the desired FISSURE install mode:
     - `full` - Includes all SDR software, network tools, and utilities 
     - `base` - Core FISSURE + GUI dependencies only (for expediting future container building)
     - `Dashboard` - GUI-only container (no SDR tools)  
     - `HIPRFISR` - Headless HIPRFISR server build
     - `SensorNode` - Sensor node build only  

3. **Run the Installer**
   ```bash
   cd FISSURE/Installer
   ./install_apptainer.sh
   ```
   This builds a writable **Apptainer sandbox** in your home directory and installs all selected software inside the container and on the host (where applicable).

4. **Launch the Container**
   ```bash
   fissure-apptainer
   ```
   This command opens a terminal inside the FISSURE container with **USB ports, audio devices, and graphics** automatically bound for hardware and GUI access.

5. **Run FISSURE**
   Once inside the container, run FISSURE just as you would on a normal system:
   ```bash
   fissure
   fissure-sensor-node
   ```
   The environment behaves like a standard install, but more isolated from the host. If you encounter issues while using FISSURE inside Apptainer, please let us know which programs, hardware, or features are not working correctly.

## Lessons

FISSURE comes with several helpful guides to become familiar with different technologies and techniques. Many include steps for using various tools that are integrated into FISSURE. We aim to improve the quality and add new content over time.
- [Lesson1: OpenBTS](/docs/Lessons/Markdown/Lesson1_OpenBTS.md)
- [Lesson2: Lua Dissectors](/docs/Lessons/Markdown/Lesson2_LuaDissectors.md)
- [Lesson3: Sound eXchange](/docs/Lessons/Markdown/Lesson3_Sound_eXchange.md)
- [Lesson4: ESP Boards](/docs/Lessons/Markdown/Lesson4_ESP_Boards.md)
- [Lesson5: Radiosonde Tracking](/docs/Lessons/Markdown/Lesson5_Radiosonde_Tracking.md)
- [Lesson6: RFID](/docs/Lessons/Markdown/Lesson6_RFID.md)
- [Lesson7: Data Types](/docs/Lessons/Markdown/Lesson7_Data_Types.md)
- [Lesson8: Custom GNU Radio Blocks](/docs/Lessons/Markdown/Lesson8_Custom_GNU_Radio_Blocks.md)
- [Lesson9: TPMS](/docs/Lessons/Markdown/Lesson9_TPMS.md)
- [Lesson10: Ham Radio Exams](/docs/Lessons/Markdown/Lesson10_Ham_Radio_Exams.md)
- [Lesson11: Wi-Fi Tools](/docs/Lessons/Markdown/Lesson11_WiFi_Tools.md)
- [Lesson12: Creating Bootable USBs](/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
- [Lesson13: Z-Wave](/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
- [Lesson14: Ceiling Fans](/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## FISSURE Challenge - Continuous Capture the Flag

<p align="center">
  <a href="https://fissure.ainfosec.com/">
    <img src="/docs/Icons/README/fissure_challenge.jpeg" alt="fissure_challenge" height="150" />
  </a>
</p>

The **FISSURE Challenge** is a continuous capture-the-flag contest built around the FISSURE framework. It is designed as an open learning tool where anyone can practice RF reverse engineering, explore new features, and tackle protocol-focused challenges.  

- New challenges are added over time as FISSURE evolves.  
- Solutions and walkthroughs are posted periodically on YouTube. [Solutions 1](https://www.youtube.com/watch?v=jYtqWwG_-kI)
- Community members are encouraged to **submit their own challenges** for others to solve.

Access the challenges at: [FISSURE Challenge](https://fissure.ainfosec.com/)

## Contributing

Suggestions for improving FISSURE are strongly encouraged. Good contribution areas include new features, installation fixes, RF protocols, hardware/SDR support, third-party tools, GNU Radio flow graphs, Python analysis scripts, plugin actions, lessons, tutorials, and documentation corrections.

The best place to start is the [Discussions](https://github.com/ainfosec/FISSURE/discussions) page, the Discord Server, email, or a focused [Issue](https://github.com/ainfosec/FISSURE/issues).

Code contributions are greatly appreciated:

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a pull request

Need more specific ideas? Check out our roadmap and running list of potential [to-do items](./TODO.md).

### Student Projects and Classroom Use

FISSURE is a good fit for senior projects, undergraduate research, graduate research, RF/cybersecurity courses, and open-source software assignments. Student teams can work on SDR hardware integration, RF protocol analysis, signal detection, IQ analysis, plugins, lessons, visualization, TAK integration, or documentation.

Students, instructors, research groups, and organizations interested in using FISSURE for hands-on RF and reverse engineering projects are encouraged to reach out.

## Commercial Support and Collaboration

Contact Assured Information Security, Inc. (AIS) Business Development to discuss FISSURE and Fracture collaboration opportunities. AIS can assist with integrating FISSURE into existing platforms and workflows, developing custom plugins and capabilities, expanding support for new hardware and sensors, and building mission-specific RF solutions.

Organizations interested in deployable Fracture systems can engage AIS to develop and integrate tactical node configurations for fixed-site, vehicle, manpack, sUAS, and fixed-wing applications. AIS can also support TAK integration, distributed sensor architectures, RF sensing and geolocation workflows, custom electronic warfare capabilities, operator training, and long-term system sustainment.

Whether your goal is research, education, prototyping, operational deployment, or integration into a larger system-of-systems architecture, AIS can help accelerate development and deployment while preserving the flexibility of the underlying FISSURE framework.  

## License

GPL-3.0

For license details, see LICENSE file.

## Contact

Join the Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Follow on Twitter/X: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Follow on Bluesky: [@fissurerf.bsky.social](https://bsky.app/profile/fissurerf.bsky.social)

Connect on LinkedIn: [FISSURE - The RF Framework](https://www.linkedin.com/company/fissure-the-rf-framework)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Testimonials

> “FISSURE is a powerful and versatile RF software platform suitable for both education and practical applications. It supports a wide range of commonly used hardware and offers intuitive IQ data analysis tools. These features enable us to visualize, interpret, and directly modify RF signal messages in our project.”  
> – Dylan R.

> “We really enjoyed using FISSURE in our engineering project. This software is an incredibly comprehensive collection of tools to manipulate radio frequencies and was an amazing aid to our studies involving wireless communications.”  
> – University Senior Project Team

## Acknowledgments

Special thanks to Dr. Samuel Mantravadi and Joseph Reith for their contributions to this project.

<img src="/docs/Icons/README/logo1.png">

## Assured Information Security

View our other open source projects at: https://ainfosec.dev/

Like working with signals, reverse engineering, or other realms in cybersecurity? Browse our [current openings](https://recruiting.paylocity.com/recruiting/jobs/All/4cc515ee-a8ad-4e3a-ac7d-c105c5d24074/ASSURED-INFORMATION-SECURITY-INC) or join our [talent community](https://recruiting.paylocity.com/Recruiting/PublicLeads/New/4cc515ee-a8ad-4e3a-ac7d-c105c5d24074) for future consideration. 

If you have an interest in hacking, check out our [Can You Hack It?®](https://www.canyouhackit.com) challenge and test your skills! Submit your score to show us what you’ve got. AIS has a national footprint with offices and remote employees across the U.S. We offer competitive pay and outstanding benefits. Join a team that is not only committed to the future of cyberspace, but to our employee’s success as well.

<p align="center">
  <a href="https://www.ainfosec.com/">
    <img src="/docs/Icons/README/ais.png" alt="ais" height="100" />
  </a>
</p>
