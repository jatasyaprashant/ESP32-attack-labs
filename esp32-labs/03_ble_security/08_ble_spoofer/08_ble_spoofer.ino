/*
 * ESP32 BLE Device Spoofer
 * Category: BLE Security
 *
 * Impersonates multiple BLE device types (Tile tracker, fitness
 * band, smart bulb, BLE HID keyboard) by cycling spoofed
 * advertisement data with correct service UUIDs every 5 seconds.
 *
 * Board  : ESP32 DevKit V1
 * Library: BLEDevice.h, BLEAdvertising.h (built-in)
 * KLS GIT Belagavi — IoT Security Lab | Authorized use only.
 */
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEAdvertising.h>

struct FakeDev { const char* name; const char* uuid; uint16_t appearance; };
FakeDev DEVS[] = {
  {"Tile_Tracker",  "0000feed-0000-1000-8000-00805f9b34fb", 0x0180},
  {"Mi_Band_7",     "0000fee0-0000-1000-8000-00805f9b34fb", 0x0180},
  {"HeartRate_Mon", "0000180d-0000-1000-8000-00805f9b34fb", 0x0341},
  {"Smart_Bulb_9A", "0000ffe0-0000-1000-8000-00805f9b34fb", 0x07C0},
  {"BLE_Keyboard",  "00001812-0000-1000-8000-00805f9b34fb", 0x03C1},
};
const int N=5; int idx=0; BLEAdvertising* pAdv;

void spoof(FakeDev& d) {
  pAdv->stop(); BLEDevice::deinit(false); BLEDevice::init(d.name);
  pAdv = BLEDevice::getAdvertising();
  BLEAdvertisementData adv;
  adv.setName(d.name); adv.setAppearance(d.appearance); adv.setFlags(0x06);
  BLEAdvertisementData scan;
  scan.setCompleteServices(BLEUUID(d.uuid));
  pAdv->setAdvertisementData(adv);
  pAdv->setScanResponseData(scan);
  pAdv->setScanResponse(true); pAdv->start();
  Serial.printf("[SPOOF] -> %-20s  UUID:%s\n       MAC:%s\n",
    d.name, d.uuid, BLEDevice::getAddress().toString().c_str());
}

void setup() {
  Serial.begin(115200);
  BLEDevice::init("ESP32"); pAdv=BLEDevice::getAdvertising();
  Serial.println("[*] BLE Device Spoofer — cycling every 5s\n");
  spoof(DEVS[0]);
}
void loop() { delay(5000); idx=(idx+1)%N; spoof(DEVS[idx]); }
