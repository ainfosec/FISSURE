/*
  ESP32 BLEBeaconSpam - A BLE Beacon spammer to test the ESP32 BLE Collector 
  or any other BLE Scan application.
  Source: https://github.com/tobozo/ESP32-BLEBeaconSpam
  MIT License
  Copyright (c) 2018 tobozo
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
  -----------------------------------------------------------------------------
*/

#include "sys/time.h"

#include "BLEDevice.h"
#include "BLEServer.h"
#include "BLEUtils.h"
#include "BLEBeacon.h"
#include "esp_sleep.h"
#include "soc/soc.h"
#include "soc/rtc_cntl_reg.h"

#include "uuidgen.h" // from https://github.com/1337ninja/UUIDGenerator
#include "compile_time.h"
#include "oui.h"

String command;
bool stringComplete = false;
String inputString = "";

RTC_DATA_ATTR static time_t last;        // remember last boot in RTC Memory
RTC_DATA_ATTR static uint32_t bootcount; // remember number of boots in RTC Memory

BLEAdvertising *pAdvertising;
struct timeval now;
UUIDGenerator uuid;


void setBeacon() {
  BLEBeacon oBeacon = BLEBeacon();
  uint16_t randomVendor = vendorList[random(0,1763)];
  byte bytes[2] = { (uint16_t)randomVendor>>8,  randomVendor};
  uint16_t manufId = (bytes[1] << 8) | bytes[0]; // sixteenBitNumber = (upperByte<<8) | lowerByte;
  Serial.print("Random vendor prefix: ");
  Serial.print(randomVendor, HEX);
  Serial.print(" = ");
  Serial.print(bytes[0], HEX);
  Serial.print(":");
  Serial.print(bytes[1], HEX);
  Serial.print(" to littleEndian => ");
  Serial.print(manufId, HEX);
  Serial.println();
  oBeacon.setManufacturerId(manufId /*0x4C00*/); // fake Apple 0x004C LSB (ENDIAN_CHANGE_U16!)
  std::string randomUUID = uuid.GenerateUUID();
  Serial.println("Random UUID : " + String ( randomUUID.c_str() ) );
  oBeacon.setProximityUUID(BLEUUID(randomUUID.c_str()/*BEACON_UUID*/));
  oBeacon.setMajor((bootcount & 0xFFFF0000) >> 16);
  oBeacon.setMinor(bootcount&0xFFFF);
  BLEAdvertisementData oAdvertisementData = BLEAdvertisementData();
  BLEAdvertisementData oScanResponseData = BLEAdvertisementData();
  oAdvertisementData.setFlags(0x04); // BR_EDR_NOT_SUPPORTED 0x04
  std::string strServiceData = "";
  strServiceData += (char)26;     // Len
  strServiceData += (char)0xFF;   // Type
  strServiceData += oBeacon.getData(); 
  oAdvertisementData.addData(strServiceData);
  pAdvertising->setAdvertisementData(oAdvertisementData);
  pAdvertising->setScanResponseData(oScanResponseData);

}




void beaconSpam() {
  long randomMacPrefix = OUIList[random(0,56)];
  Serial.print("Random mac prefix: ");
  Serial.println(randomMacPrefix, HEX);
  byte bytes[3] = { ((long)randomMacPrefix>>16), (long)randomMacPrefix>>8,  randomMacPrefix};
  uint8_t new_mac[8] = {bytes[0],bytes[1],bytes[2],random(0,255),random(0,255),random(0,255)};
  esp_base_mac_addr_set(new_mac);
  Serial.print("New Mac: ");
  for(int i=0;i<6;i++) {
    Serial.print(new_mac[i], HEX);
    if(i<5) Serial.print(":");
  }
  Serial.println();
  last = now.tv_sec;
  //btStart();
  // Create the BLE Device
  BLEDevice::init("");
  // Create the BLE Server
  BLEServer *pServer = BLEDevice::createServer();
  pAdvertising = pServer->getAdvertising();
  setBeacon();
   // Start advertising
  pAdvertising->start();
  //Serial.println("Advertizing started...");
  delay(100);
  pAdvertising->stop();
  BLEDevice::deinit();
  //btStop();
}

void IRAM_ATTR serialEvent(){
  while(Serial.available()){
    String inputString = Serial.readStringUntil('\n');
    command = inputString;
    stringComplete = true;
    }
}


void setup() {
  Serial.begin(115200);
  WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0); //disable brownout detector
  
}



void loop() {
  serialEvent();
  if (stringComplete) {
    if (command == "attack") {
      gettimeofday(&now, NULL);
      if(now.tv_sec <= 1) {
        Serial.println("First run, setting time");
        struct timeval tv;
        tv.tv_sec = __TIME_UNIX__;
        settimeofday(&tv, NULL);
      }
      // create some real randomness for the dumb uuidgen
      int randomLoopSize = random(0, 100 + now.tv_sec%100 );
      for(int i=0;i<randomLoopSize;i++) {
        std::string randomUUID = uuid.GenerateUUID();
      }
      //Serial.printf("start ESP32 %d\n",bootcount++);
      //Serial.printf("deep sleep (%lds since last reset, %lds since last boot)\n",now.tv_sec,now.tv_sec-last);
      beaconSpam();
      //Serial.printf("enter deep sleep\n");
      //esp_deep_sleep(100000LL); // sleep 100ms
      //ESP.restart();
      //Serial.printf("in deep sleep\n");
    }
    else if (command == "stop") {

      Serial.println("Stopping attack");
      stringComplete = false;
      inputString = "";
      ESP.restart();
    }


    else {
      Serial.println("Unknown command, use attack or stop.");
      inputString = "";
      stringComplete = false;
    }
  }
}
