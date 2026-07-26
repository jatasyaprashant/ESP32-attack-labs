/*
 * ESP32 BLE Active Scanner
 * Category: BLE Security
 *
 * Performs active BLE scanning and reports all nearby devices:
 * name, MAC, address type, RSSI, service UUIDs, appearance
 * value, and manufacturer data with vendor identification.
 *
 * Board  : ESP32 DevKit V1
 * Library: BLEDevice.h, BLEScan.h (built-in ESP32 Arduino core)
 * KLS GIT Belagavi — IoT Security Lab | Authorized use only.
 */
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

BLEScan* pScan;

class ScanCB : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice dev) {
    Serial.printf("\n[BLE] %-28s  %s  RSSI:%d\n",
      dev.getName().length() ? dev.getName().c_str() : "(hidden)",
      dev.getAddress().toString().c_str(), dev.getRSSI());
    Serial.printf("      AddrType : %s\n",
      dev.getAddress().getType()==BLE_ADDR_TYPE_PUBLIC ? "PUBLIC" : "RANDOM");
    if (dev.haveServiceUUID())
      Serial.printf("      SvcUUID  : %s\n", dev.getServiceUUID().toString().c_str());
    if (dev.haveManufacturerData()) {
      std::string md = dev.getManufacturerData();
      Serial.printf("      MfrData  : ");
      for (uint8_t c : md) Serial.printf("%02X ", c);
      if (md.size() >= 2) {
        uint16_t vid = (uint8_t)md[0] | ((uint8_t)md[1]<<8);
        if      (vid==0x004C) Serial.print("(Apple)");
        else if (vid==0x0006) Serial.print("(Microsoft)");
        else if (vid==0x0075) Serial.print("(Samsung)");
        else if (vid==0x00E0) Serial.print("(Google)");
      }
      Serial.println();
    }
    if (dev.haveAppearance())
      Serial.printf("      Appearance: 0x%04X\n", dev.getAppearance());
  }
};

void setup() {
  Serial.begin(115200);
  BLEDevice::init("ESP32_Scanner");
  pScan = BLEDevice::getScan();
  pScan->setAdvertisedDeviceCallbacks(new ScanCB());
  pScan->setActiveScan(true);
  pScan->setInterval(100); pScan->setWindow(99);
  Serial.println("[*] BLE Active Scanner running\n");
}

void loop() {
  Serial.println("\n[*] Scanning 5 sec...");
  BLEScanResults r = pScan->start(5, false);
  Serial.printf("[*] Found: %d devices\n", r.getCount());
  pScan->clearResults();
  delay(3000);
}
