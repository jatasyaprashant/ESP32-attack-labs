# 🔐 ESP32 Attack Labs

> **IoT Cybersecurity Training — KLS Gogte Institute of Technology, Belagavi**
> **For authorized educational use only in isolated lab environments.**

A complete collection of **14 ESP32-based cybersecurity attack and reconnaissance modules** built on the Arduino framework. Designed for hands-on IoT security training on the ESP32 DevKit V1.

---

## ⚠️ Legal & Ethical Notice

All tools in this repository are for **authorized academic and research use only**.  
- Use only on networks and devices **you own or have explicit written permission** to test.  
- Unauthorized use is illegal under the IT Act 2000 (India) and equivalent laws worldwide.  
- Run all experiments in an **isolated lab environment** (no internet-connected devices nearby).

---

## 🛠 Requirements

| Item | Details |
|---|---|
| **Board** | ESP32 DevKit V1 (any ESP32 with Arduino support) |
| **IDE** | Arduino IDE 2.x or PlatformIO |
| **ESP32 Core** | `espressif/arduino-esp32` v2.x or v3.x |
| **Board URL** | `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json` |

### External Libraries (install via Library Manager)
| Module | Library |
|---|---|
| MQTT Brute Force | `PubSubClient` by Nick O'Leary |

All other libraries are bundled with the ESP32 Arduino core.

---

## 📁 Repository Structure

```
ESP32-attack-labs/
├── 01_wifi_recon/
│   ├── 01_wifi_scanner/          # Active AP scanner
│   ├── 02_probe_sniffer/         # Passive probe request capture
│   └── 03_packet_sniffer/        # Full 802.11 monitor mode
│
├── 02_wifi_attacks/
│   ├── 04_deauth_attack/         # 802.11 deauth frame injection
│   ├── 05_evil_twin/             # Rogue AP + captive portal
│   └── 06_beacon_flood/          # Fake AP DoS
│
├── 03_ble_security/
│   ├── 07_ble_scanner/           # BLE active scanner
│   └── 08_ble_spoofer/           # BLE device impersonation
│
├── 04_network_attacks/
│   ├── 09_mqtt_bruteforce/       # MQTT credential attack
│   ├── 10_http_bruteforce/       # HTTP Basic Auth attack
│   └── 11_port_scanner/          # IoT TCP port scanner
│
└── 05_hardware_security/
    ├── 12_i2c_scanner/           # I2C bus device discovery
    ├── 13_eeprom_dumper/         # AT24Cxx EEPROM hex dump
    └── 14_spiffs_inspector/      # Internal flash forensics
```

---

## 📡 Category 1 — WiFi Reconnaissance

### 01. WiFi Network Scanner
Performs an active WiFi scan and displays all nearby access points in a formatted table with SSID, BSSID, channel, RSSI, and encryption type.

**Key concepts:** `WiFi.scanNetworks()`, `WIFI_STA` mode, encryption type enum

---

### 02. Probe Request Sniffer
Passively captures 802.11 Probe Request management frames. Reveals the list of SSIDs every nearby device has previously connected to — without transmitting anything.

**Key concepts:** Promiscuous mode, frame control filtering (`0x0040`), channel hopping

---

### 03. Promiscuous Packet Sniffer
Full monitor mode — captures and classifies all 802.11 frame types (beacons, auth, deauth, probe, data) with source/destination MACs and RSSI. Hops all 13 channels.

**Key concepts:** `WIFI_PROMIS_FILTER_MASK_ALL`, `ieee80211` frame parsing, `IRAM_ATTR`

---

## ⚡ Category 2 — WiFi Attacks

### 04. Deauthentication Attack
Injects crafted 802.11 Deauthentication frames to forcibly disconnect a target client from its AP. Demonstrates the unprotected management frame vulnerability in WPA2 (mitigated by 802.11w/PMF).

**Setup:** Edit `AP_MAC`, `CLI_MAC`, `CH` before flashing.  
**Key concepts:** Raw frame injection, `esp_wifi_80211_tx()`, reason codes

---

### 05. Evil Twin AP + Captive Portal
Creates a rogue open AP cloning a target SSID. A DNS server hijacks all queries and redirects clients to a credential-harvesting login page served by the ESP32.

**Setup:** Edit `AP_SSID`.  
**Key concepts:** `WiFi.softAP()`, `DNSServer`, captive portal, HTTP POST capture

---

### 06. Beacon Flood
Injects 802.11 beacon frames with randomized source MACs to fill the 2.4 GHz band with ghost access points. Demonstrates a denial-of-service attack against WiFi scanners.

**Key concepts:** Raw beacon frame construction, supported rates IE, DS parameter set IE

---

## 🔵 Category 3 — BLE Security

### 07. BLE Active Scanner
Performs active BLE scanning and reports all nearby devices with name, MAC address type, RSSI, service UUIDs, appearance value, and manufacturer data (with Bluetooth SIG company ID lookup).

**Key concepts:** `BLEScan`, `BLEAdvertisedDeviceCallbacks`, manufacturer data parsing

---

### 08. BLE Device Spoofer
Impersonates multiple BLE device types (Tile tracker, fitness band, smart bulb, BLE HID keyboard) by cycling spoofed advertisement data with correct service UUIDs every 5 seconds.

**Key concepts:** `BLEAdvertisementData`, service UUID spoofing, appearance values

---

## 🌐 Category 4 — Network Protocol Attacks

### 09. MQTT Credential Brute Forcer
Dictionary attack against an MQTT broker. On a successful login, immediately subscribes to the `#` wildcard topic to intercept every message published to the broker.

**Setup:** Edit `MQTT_HOST`, optionally extend credential lists.  
**Key concepts:** `PubSubClient`, `mqtt.connect()` return codes, wildcard subscription

---

### 10. HTTP Basic Auth Brute Forcer
Dictionary attack against HTTP Basic Authentication endpoints. Targets IoT admin panels and routers. Reports HTTP status per attempt and halts on first success (200/302).

**Setup:** Edit `TARGET` URL.  
**Key concepts:** Base64 encoding, `Authorization: Basic` header, HTTP status interpretation

---

### 11. IoT Port Scanner
TCP connect scan across 16 IoT-critical protocol ports (MQTT, CoAP, Modbus, OPC-UA, MongoDB, Redis, Elasticsearch, BACnet). Performs banner grabbing on open ports.

**Setup:** Edit `TARGET_IP`.  
**Key concepts:** `WiFiClient.connect()` with timeout, banner grabbing, protocol port mapping

---

## 🔧 Category 5 — Hardware Security

### 12. I2C Bus Scanner
Probes all 127 I2C addresses to discover connected chips. Automatically identifies 16 common device types: EEPROMs, IMUs, OLED displays, RTC modules, ADCs, and environmental sensors.

**Wiring:** SDA → GPIO21 | SCL → GPIO22  
**Key concepts:** `Wire.beginTransmission()`, address space probing, device identification

---

### 13. I2C EEPROM Hex Dumper
Full hex + ASCII dump of AT24Cxx series EEPROMs. Can expose hardcoded WiFi credentials, API keys, TLS certificates, or device configuration stored in external non-volatile memory.

**Wiring:** SDA → GPIO21 | SCL → GPIO22  
**Setup:** Change `EEPROM_SIZE` to `32768` for AT24C256.  
**Key concepts:** 16-bit EEPROM addressing, sequential read, hex/ASCII formatting

---

### 14. SPIFFS Flash Inspector
Mounts the ESP32 internal SPIFFS filesystem, lists all files with content preview, then scans for known sensitive filenames (config, credentials, API keys, certificates) commonly found in IoT firmware.

**Key concepts:** `SPIFFS.begin()`, `FS.h`, sensitive file enumeration, content preview

---

## 🚀 Quick Start

1. Install the ESP32 board package in Arduino IDE
2. Open any `.ino` file in its folder
3. Select **ESP32 Dev Module** as the board
4. Set **Upload Speed** to `115200`
5. Edit the `CONFIG` section at the top of each sketch
6. Flash and open Serial Monitor at `115200` baud

---

## 📚 Learning Objectives

After completing all lab modules, students will be able to:

- [ ] Perform passive and active WiFi reconnaissance
- [ ] Demonstrate WPA2 management frame vulnerabilities  
- [ ] Set up rogue AP attacks with credential harvesting
- [ ] Scan and enumerate BLE devices and their services
- [ ] Test MQTT and HTTP authentication weaknesses
- [ ] Perform IoT network protocol port scanning
- [ ] Conduct hardware-level I2C bus enumeration
- [ ] Extract and analyze EEPROM and flash memory contents

---

## 🔗 References

- [ESP32 Arduino Core](https://github.com/espressif/arduino-esp32)
- [ESP-IDF WiFi API](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/network/esp_wifi.html)
- [IEEE 802.11 Standard](https://standards.ieee.org/ieee/802.11/7028/)
- [OWASP IoT Attack Surface Areas](https://owasp.org/www-project-iot/)

---

*KLS Gogte Institute of Technology, Belagavi, Karnataka*  
*IoT Cybersecurity Lab — Research by Prashant Badiger*
