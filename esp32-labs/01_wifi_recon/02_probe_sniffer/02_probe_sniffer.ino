/*
 * ESP32 Probe Request Sniffer
 * Category: WiFi Reconnaissance
 *
 * Passively captures 802.11 Probe Request frames to reveal
 * every SSID a nearby device has previously connected to.
 * Channel-hops every 500 ms across all 13 channels.
 *
 * Board  : ESP32 DevKit V1
 * Library: esp_wifi.h, nvs_flash.h (ESP-IDF bundled)
 * KLS GIT Belagavi — IoT Security Lab | Authorized use only.
 */
#include <esp_wifi.h>
#include <nvs_flash.h>
#include <map>
#include <set>
#include <string>

std::map<std::string, std::set<std::string>> seen;

typedef struct {
  unsigned frame_ctrl:16, duration:16;
  uint8_t  dst[6], src[6], bssid[6];
  unsigned seq:16;
} mgmt_hdr_t;

void IRAM_ATTR sniffCB(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  wifi_promiscuous_pkt_t* p = (wifi_promiscuous_pkt_t*)buf;
  mgmt_hdr_t* h = (mgmt_hdr_t*)p->payload;
  if ((h->frame_ctrl & 0x00FC) != 0x0040) return;

  uint8_t* body = p->payload + sizeof(mgmt_hdr_t);
  uint8_t ssid_len = body[1];
  char ssid[33] = "<any>";
  if (body[0]==0 && ssid_len>0 && ssid_len<33) {
    memcpy(ssid, body+2, ssid_len); ssid[ssid_len]=0;
  }
  char mac[18];
  snprintf(mac,18,"%02X:%02X:%02X:%02X:%02X:%02X",
    h->src[0],h->src[1],h->src[2],h->src[3],h->src[4],h->src[5]);
  std::string m(mac), s(ssid);
  if (!seen[m].count(s)) {
    seen[m].insert(s);
    Serial.printf("[PROBE] %s -> \"%s\" (RSSI:%d)\n", mac, ssid, p->rx_ctrl.rssi);
  }
}

int ch=1; unsigned long lastHop=0;

void setup() {
  Serial.begin(115200);
  nvs_flash_init();
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffCB);
  Serial.println("[*] Probe sniffer active — channel hopping\n");
}

void loop() {
  if (millis()-lastHop > 500) {
    ch = (ch%13)+1;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    lastHop = millis();
  }
}
