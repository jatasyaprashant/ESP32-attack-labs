/*
 * ESP32 Promiscuous Packet Sniffer
 * Category: WiFi Reconnaissance
 *
 * Full monitor mode — captures all 802.11 frame types
 * (beacon, probe, auth, deauth, data) across all channels
 * with source/destination MACs and RSSI.
 *
 * Board  : ESP32 DevKit V1
 * Library: esp_wifi.h, nvs_flash.h (ESP-IDF bundled)
 * KLS GIT Belagavi — IoT Security Lab | Authorized use only.
 */
#include <esp_wifi.h>
#include <nvs_flash.h>

typedef struct {
  unsigned fc:16, dur:16;
  uint8_t addr1[6], addr2[6], addr3[6];
  unsigned seq:16;
} ieee80211_t;

const char* ftype(uint16_t fc) {
  switch((fc>>2)&0x3F) {
    case 0x04: return "PROBE-REQ";
    case 0x08: return "BEACON   ";
    case 0x0B: return "AUTH     ";
    case 0x0C: return "DEAUTH   ";
    case 0x20: return "DATA     ";
    default:   return "OTHER    ";
  }
}

void IRAM_ATTR rxCB(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t* p = (wifi_promiscuous_pkt_t*)buf;
  ieee80211_t* h = (ieee80211_t*)p->payload;
  Serial.printf("[%s] CH:%2d RSSI:%4d SRC:%02X:%02X:%02X:%02X:%02X:%02X DST:%02X:%02X:%02X:%02X:%02X:%02X\n",
    ftype(h->fc), p->rx_ctrl.channel, p->rx_ctrl.rssi,
    h->addr2[0],h->addr2[1],h->addr2[2],h->addr2[3],h->addr2[4],h->addr2[5],
    h->addr1[0],h->addr1[1],h->addr1[2],h->addr1[3],h->addr1[4],h->addr1[5]);
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
  wifi_promiscuous_filter_t f = {.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL};
  esp_wifi_set_promiscuous_filter(&f);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&rxCB);
  Serial.println("[*] Monitor mode ON — all 802.11 frames\n");
}

void loop() {
  if (millis()-lastHop > 1000) {
    ch = (ch%13)+1;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    Serial.printf("\n--- CH %d ---\n", ch);
    lastHop = millis();
  }
}
