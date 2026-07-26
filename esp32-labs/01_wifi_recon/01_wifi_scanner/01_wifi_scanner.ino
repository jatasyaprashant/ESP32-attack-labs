/*
 * ESP32 WiFi Network Scanner
 * Category: WiFi Reconnaissance
 *
 * Scans all nearby access points and displays SSID, BSSID,
 * channel, signal strength (RSSI) and encryption type.
 * Foundation module for WiFi target identification.
 *
 * Board  : ESP32 DevKit V1
 * Library: WiFi.h (built-in ESP32 Arduino core)
 * KLS GIT Belagavi — IoT Security Lab | Authorized use only.
 */
#include <WiFi.h>

const char* encStr(wifi_auth_mode_t e) {
  switch(e) {
    case WIFI_AUTH_OPEN:            return "OPEN";
    case WIFI_AUTH_WEP:             return "WEP";
    case WIFI_AUTH_WPA_PSK:         return "WPA";
    case WIFI_AUTH_WPA2_PSK:        return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:    return "WPA/WPA2";
    case WIFI_AUTH_WPA3_PSK:        return "WPA3";
    default:                        return "UNK";
  }
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  Serial.println("\n[*] ESP32 WiFi Network Scanner");
}

void loop() {
  int n = WiFi.scanNetworks();
  Serial.printf("\n[*] Found %d APs:\n", n);
  Serial.println(" # | SSID                       | BSSID             | CH | RSSI | ENC");
  Serial.println("---+----------------------------+-------------------+----+------+-------");
  for (int i = 0; i < n; i++) {
    Serial.printf("%2d | %-26s | %s | %2d | %4d | %s\n",
      i+1, WiFi.SSID(i).c_str(), WiFi.BSSIDstr(i).c_str(),
      WiFi.channel(i), WiFi.RSSI(i), encStr(WiFi.encryptionType(i)));
  }
  WiFi.scanDelete();
  delay(5000);
}
