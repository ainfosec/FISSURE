---
This lesson will show methods for creating a bootable USB to contain FISSURE and third-party tools. This is desirable for classroom environments or any situation that can benefit from a uniform software environment. FISSURE will install several GBs of third-party tools and there will not be enough space to store everything (along with the OS) on a 32 GB USB drive.  It is recommended to use a larger USB size or select only a subset of the software during the FISSURE installation that will meet your requirements.

## Table of Contents
1. [Systemback](#systemback)
2. [guidus](#guidus)
3. [BIOS Settings](#bios)
4. [Cloning USBs](#cloning)


<div id="systemback"/> 

## Systemback

Systemback will create an image file of your operating system that can be copied by another program such as guidus. Follow the installation instructions below or check if it was installed as part of FISSURE.

- https://github.com/BluewhaleRobot/systemback

To launch: 

```sudo systemback```

Select "Live system create" and "Create new"

![systemback1](./Images/Lesson12_systemback1.png)

![systemback2](./Images/Lesson12_systemback2.png)

<div id="guidus"/>   

## guidus

Mkusb is a tool to create a bootable drive from an iso image or a compressed image file (systemback). It can be used on mass storage devices such as a USB drive, an internal drive, or an eSATA drive. It allows for the creation of persistent (retains data on reboot) and non-persistent USB Linux installations. Separate partitions can be included to maintain generic USB storage functionality outside of the bootable drive. 

- https://help.ubuntu.com/community/mkusb

The GUI version of mkusb can be launched with:

```sudo guidus```

Select "Install (make a boot device)" and follow the prompts to create either a "Live-only" or "Persistent live" USB. Refer to the mkusb link for background information about the specific methods. guidus can also be used to wipe and restore a USB after it is converted to a bootable drive. It is safer to install all necessary software prior to creating the bootable USB to ensure there is enough space and that everything gets installed to the right file system locations.

![guidus1](./Images/Lesson12_guidus1.png)

![guidus2](./Images/Lesson12_guidus2.png)

<div id="bios"/>   

## BIOS Settings

Many computers will not have the option to boot from a USB without modifying the BIOS settings. For Dell computers this usually entails enabling Legacy boot ("F2" to access BIOS) and then pressing "F12" to access the one-time boot menu and selecting the USB option. Make sure the BIOS is not locked out and there are no other security measures preventing the computer from booting off the USB.

<div id="cloning"/>   

## Cloning USBs

After a USB has been successfully created, it is often the case that duplicates are needed. It helps to have multiple copies of the same USB as sizes can vary slightly between models that state they are the same size. Copying to a smaller sized USB can ruin the image and will require modification to truncate it. It is usually faster to copy the image from a hard drive vs. directly from one USB to another.

There is more than one way to clone a USB. Using the dd command is an easy method.

1. Identify the location of the USB with: `sudo fdisk -l`
2. Copy the original USB image: `sudo dd if=/dev/sda of=/path/to/image.img conv=sync,noerror status=progress`
3. Copy image to the new USB: `sudo dd if=/path/to/image.img of=/dev/sda conv=sync,noerror status=progress`
