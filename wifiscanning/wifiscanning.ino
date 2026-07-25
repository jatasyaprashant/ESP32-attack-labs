#include <WiFi.h>

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println();
  Serial.println("ESP32 WiFi Scanner");
  Serial.println("------------------");

  // Put WiFi into Station mode
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  Serial.println("Scanning for WiFi networks...");
}

void loop() {
  Serial.println("\nStarting Scan...");

  int networkCount = WiFi.scanNetworks();

  if (networkCount == 0) {
    Serial.println("No WiFi networks found.");
  } else {
    Serial.printf("Found %d network(s):\n\n", networkCount);

    for (int i = 0; i < networkCount; i++) {
      Serial.printf("[%d]\n", i + 1);
      Serial.printf("SSID      : %s\n", WiFi.SSID(i).c_str());
      Serial.printf("RSSI      : %d dBm\n", WiFi.RSSI(i));
      Serial.printf("Channel   : %d\n", WiFi.channel(i));

      Serial.print("Encryption: ");
      switch (WiFi.encryptionType(i)) {
        case WIFI_AUTH_OPEN:
          Serial.println("Open");
          break;
        case WIFI_AUTH_WEP:
          Serial.println("WEP");
          break;
        case WIFI_AUTH_WPA_PSK:
          Serial.println("WPA");
          break;
        case WIFI_AUTH_WPA2_PSK:
          Serial.println("WPA2");
          break;
        case WIFI_AUTH_WPA_WPA2_PSK:
          Serial.println("WPA/WPA2");
          break;
        case WIFI_AUTH_WPA2_ENTERPRISE:
          Serial.println("WPA2 Enterprise");
          break;
        case WIFI_AUTH_WPA3_PSK:
          Serial.println("WPA3");
          break;
        case WIFI_AUTH_WPA2_WPA3_PSK:
          Serial.println("WPA2/WPA3");
          break;
        default:
          Serial.println("Unknown");
      }

      Serial.printf("BSSID     : %s\n", WiFi.BSSIDstr(i).c_str());
      Serial.println("------------------------------");
    }
  }

  WiFi.scanDelete();

  Serial.println("Waiting 10 seconds before next scan...");
  delay(10000);
}