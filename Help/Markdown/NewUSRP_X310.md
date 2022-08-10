# New USRP X310:

1. Plug 10 GbE into second slot on USRP
2. Set computer IP to 192.168.40.1. Ping 192.168.40.2. Run `uhd_find_devices`. If there is an RFNOC error about a missing folder, download a UHD release and copy the folder:
3. `wget https://codeload.github.com/EttusResearch/uhd/zip/release_003_010_003_000 -O uhd.zip`
4. `unzip uhd.zip`
5. `cd uhd-release_003_010_003_000/host/include`
6. `sudo cp -Rv uhd/rfnoc /usr/share/uhd/`
7. Try to run flow graph. It will print out instructions for matching FPGA images for current version of UHD.
8. `/home/user/lib/uhd/utils/uhd_images_downloader.py` or  `/usr/lib/uhd/utils/uhd_images_downloader.py`
9. `/home/user/bin/uhd_image_loader --args="type=x300,addr=192.168.40.2"` or `/usr/bin/uhd_image_loader" --args="type=x300,addr=192.168.140.2"`
10. Set MTU to 9000 for the 10 GbE network connection.
11. Change IP address of USRP 10 GbE connection as needed:
```
cd usr/lib/uhd/utils
./usrp_burn_mb_eeprom --args=<optional device args> --values="ip-addr3=192.168.140.2"
```
12. Adjust this value to something like: `sudo sysctl -w net.core.wmem_max=24862979`
