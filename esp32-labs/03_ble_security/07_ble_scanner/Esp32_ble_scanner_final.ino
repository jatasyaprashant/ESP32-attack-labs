/*
 * ╔══════════════════════════════════════════════════════════╗
 * ║       ESP32 BLE Advanced Scanner — Final Version        ║
 * ║       ESP32 Arduino Core v3.x (IDF 5.x)                 ║
 * ╠══════════════════════════════════════════════════════════╣
 * ║  Features:                                               ║
 * ║  • Crash-safe — all Serial.printf outside callback       ║
 * ║  • Apple frame decoder (iPhone/AirTag/AirPods/Hotspot)   ║
 * ║  • 20+ Bluetooth SIG vendor IDs                          ║
 * ║  • 30+ OUI (MAC prefix) manufacturer lookup              ║
 * ║  • Known service UUID identification                     ║
 * ║  • Embedded IP address detection in MfrData              ║
 * ║  • Smart device type guesser                             ║
 * ║  • GATT name resolution for PUBLIC unnamed devices       ║
 * ║  • RSSI signal quality + rough distance estimate         ║
 * ║  • Cross-scan device persistence tracking                ║
 * ║  • Full classified summary per scan                      ║
 * ╠══════════════════════════════════════════════════════════╣
 * ║  Board  : ESP32 DevKit V1                                ║
 * ║  Library: BLEDevice.h (built-in ESP32 Arduino Core v3.x) ║
 * ║  KLS GIT Belagavi — IoT Security Lab                     ║
 * ║  Authorized educational use only.                        ║
 * ╚══════════════════════════════════════════════════════════╝
 */

#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <BLEClient.h>
#include <BLERemoteService.h>
#include <BLERemoteCharacteristic.h>

// ═══════════════════════════════════════════════════════════
//  CONFIGURATION
// ═══════════════════════════════════════════════════════════
#define SCAN_DURATION   8       // seconds per scan
#define SCAN_INTERVAL   4000    // ms between scans
#define MAX_DEVS        50      // max devices per scan
#define MAX_TRACKED     80      // max devices tracked across scans

// ═══════════════════════════════════════════════════════════
//  DEVICE RECORD (per scan)
// ═══════════════════════════════════════════════════════════
struct BLERecord {
  String   mac;
  String   name;
  bool     isPublic;
  int      rssi;
  int8_t   txPower;
  bool     hasTxPower;
  String   svcUUID;
  String   mfrHex;
  uint16_t mfrVid;
  uint8_t  appleType;
  bool     hasAppearance;
  uint16_t appearance;
  bool     connectable;
  String   embeddedIP;
};

BLERecord recs[MAX_DEVS];
int recCount = 0;

// ═══════════════════════════════════════════════════════════
//  CROSS-SCAN TRACKER
// ═══════════════════════════════════════════════════════════
struct TrackedDev {
  String mac;
  String name;
  int    seenCount;
  int    firstScan;
  int    lastRssi;
};

TrackedDev tracked[MAX_TRACKED];
int trackedCount = 0;

void trackDevice(const String& mac, const String& name, int rssi, int scanNum) {
  for (int i = 0; i < trackedCount; i++) {
    if (tracked[i].mac == mac) {
      tracked[i].seenCount++;
      tracked[i].lastRssi = rssi;
      if (name.length()) tracked[i].name = name;
      return;
    }
  }
  if (trackedCount < MAX_TRACKED) {
    tracked[trackedCount].mac       = mac;
    tracked[trackedCount].name      = name;
    tracked[trackedCount].seenCount = 1;
    tracked[trackedCount].firstScan = scanNum;
    tracked[trackedCount].lastRssi  = rssi;
    trackedCount++;
  }
}

// ═══════════════════════════════════════════════════════════
//  APPLE FRAME TYPE DECODER
// ═══════════════════════════════════════════════════════════
const char* appleFrame(uint8_t t) {
  switch (t) {
    case 0x02: return "iBeacon";
    case 0x03: return "AirPrint";
    case 0x05: return "AirDrop";
    case 0x07: return "AirPods / Beats Headphones";
    case 0x08: return "Siri Remote";
    case 0x09: return "AirPlay Target";
    case 0x0A: return "AirPlay Source";
    case 0x0B: return "Apple Watch Pairing";
    case 0x0C: return "Handoff (Continuity)";
    case 0x0D: return "WiFi Password Sharing";
    case 0x0E: return "Instant Hotspot";
    case 0x0F: return "Nearby Action";
    case 0x10: return "Nearby Info  [iPhone / iPad ACTIVE]";
    case 0x12: return "FindMy  [AirTag / Lost Device]";
    case 0x13: return "iCloud Private Relay";
    case 0x15: return "Proximity Pairing  [AirPods]";
    case 0x16: return "Hey Siri";
    case 0x17: return "AirPods Pro (2nd gen)";
    default:   return "Apple (unknown frame)";
  }
}

// ═══════════════════════════════════════════════════════════
//  BLUETOOTH SIG VENDOR IDs
// ═══════════════════════════════════════════════════════════
const char* vendorName(uint16_t vid) {
  switch (vid) {
    case 0x004C: return "Apple";
    case 0x0006: return "Microsoft";
    case 0x0075: return "Samsung";
    case 0x00E0: return "Google";
    case 0x0087: return "Garmin";
    case 0x0157: return "Xiaomi";
    case 0x0171: return "Amazon";
    case 0x01D8: return "Tile";
    case 0x02E5: return "Fitbit";
    case 0x0310: return "Espressif Systems";
    case 0x059D: return "Huawei";
    case 0x05A7: return "Sonos";
    case 0x0089: return "Suunto";
    case 0x0154: return "Polar Electro";
    case 0x0499: return "Ruuvi Innovations";
    case 0x0105: return "Wahoo Fitness";
    case 0x00D0: return "iRobot";
    case 0x0046: return "Motorola";
    case 0x000F: return "Broadcom";
    case 0x0025: return "Nokia";
    case 0x0053: return "Harman";
    case 0x007D: return "Logitech";
    case 0x00AC: return "Interaxon (Muse)";
    case 0x0822: return "Realtek";
    case 0x0837: return "OPPO / OnePlus";
    default:     return nullptr;
  }
}

// ═══════════════════════════════════════════════════════════
//  OUI (MAC PREFIX) MANUFACTURER LOOKUP
// ═══════════════════════════════════════════════════════════
struct OUI { const char* prefix; const char* name; };
const OUI OUI_TABLE[] = {
  // Espressif (ESP32)
  {"24:6F:28", "Espressif (ESP32)"},
  {"30:AE:A4", "Espressif (ESP32)"},
  {"3C:71:BF", "Espressif (ESP32)"},
  {"84:0D:8E", "Espressif (ESP32)"},
  {"A4:CF:12", "Espressif (ESP32)"},
  {"EC:FA:BC", "Espressif (ESP32)"},
  {"E0:98:06", "Espressif (ESP32)"},
  // Apple
  {"AC:BC:32", "Apple"},
  {"B8:5D:0A", "Apple"},
  {"F4:D3:A8", "Apple"},
  {"3C:06:30", "Apple"},
  {"B4:77:45", "Apple"},   // AirPort / Apple TV
  // Samsung
  {"8C:77:12", "Samsung"},
  {"CC:07:AB", "Samsung"},
  {"84:38:35", "Samsung"},
  // Xiaomi
  {"00:EC:0A", "Xiaomi"},
  {"28:6C:07", "Xiaomi"},
  {"64:64:4A", "Xiaomi"},
  // Google
  {"F4:F5:D8", "Google"},
  {"3C:5A:B4", "Google"},
  // Amazon
  {"FC:65:DE", "Amazon"},
  {"74:C2:46", "Amazon"},
  // Texas Instruments
  {"00:12:4B", "Texas Instruments"},
  {"00:17:E9", "Texas Instruments"},
  // Nordic Semi
  {"E5:46:DA", "Nordic Semi"},
  // Raspberry Pi
  {"B8:27:EB", "Raspberry Pi"},
  {"DC:A6:32", "Raspberry Pi"},
  // OnePlus/OPPO
  {"AC:F7:F3", "OnePlus"},
  // Realtek
  {"00:E0:4C", "Realtek"},
};
const int OUI_COUNT = sizeof(OUI_TABLE) / sizeof(OUI_TABLE[0]);

const char* ouiLookup(const String& mac) {
  String prefix = mac.substring(0, 8);
  prefix.toUpperCase();
  for (int i = 0; i < OUI_COUNT; i++) {
    if (prefix == OUI_TABLE[i].prefix)
      return OUI_TABLE[i].name;
  }
  return nullptr;
}

// ═══════════════════════════════════════════════════════════
//  KNOWN SERVICE UUID DECODER
// ═══════════════════════════════════════════════════════════
const char* decodeSvcUUID(const String& uuid) {
  String u = uuid;
  u.toLowerCase();
  // Standard GATT services (16-bit)
  if (u.indexOf("0000180d") >= 0) return "Heart Rate Monitor";
  if (u.indexOf("0000180f") >= 0) return "Battery Service";
  if (u.indexOf("00001810") >= 0) return "Blood Pressure";
  if (u.indexOf("00001816") >= 0) return "Cycling Speed/Cadence";
  if (u.indexOf("00001818") >= 0) return "Cycling Power";
  if (u.indexOf("0000181c") >= 0) return "User Data";
  if (u.indexOf("00001812") >= 0) return "HID (Keyboard/Mouse)";
  if (u.indexOf("0000ffe0") >= 0) return "IoT Serial (HM-10 style)";
  if (u.indexOf("0000fff0") >= 0) return "IoT Custom Service";
  if (u.indexOf("0000fee0") >= 0) return "Xiaomi / Mi Band";
  if (u.indexOf("0000feed") >= 0) return "Tile Tracker";
  // Google
  if (u.indexOf("0000fd69") >= 0) return "Google Fast Pair / Nearby Share";
  if (u.indexOf("0000fe9f") >= 0) return "Google (Cast/Chromecast)";
  if (u.indexOf("0000fea0") >= 0) return "Google";
  // Apple Continuity
  if (u.indexOf("7905f431") >= 0) return "Apple Continuity";
  if (u.indexOf("89d3502b") >= 0) return "Apple Notification Center (ANCS)";
  // Other
  if (u.indexOf("60910001") >= 0) return "Smart Home Proprietary";
  if (u.indexOf("6e400001") >= 0) return "Nordic UART Service (NUS)";
  if (u.indexOf("a8b3fb43") >= 0) return "Wahoo Fitness";
  return nullptr;
}

// ═══════════════════════════════════════════════════════════
//  DEVICE TYPE GUESSER
// ═══════════════════════════════════════════════════════════
String guessDeviceType(const BLERecord& r) {
  // Apple frame-based
  if (r.mfrVid == 0x004C) {
    switch (r.appleType) {
      case 0x07: case 0x15: return "AirPods / Beats";
      case 0x10: return "iPhone / iPad";
      case 0x12: return "AirTag";
      case 0x0E: return "iPhone Hotspot";
      case 0x05: return "Mac (AirDrop)";
      case 0x09: return "Apple TV / HomePod";
      default:   return "Apple Device";
    }
  }
  // By service UUID
  if (r.svcUUID.length()) {
    const char* svc = decodeSvcUUID(r.svcUUID);
    if (svc) return String(svc);
    if (r.svcUUID.indexOf("fd69") >= 0) return "Android Phone";
    if (r.svcUUID.indexOf("fe9f") >= 0) return "Chromecast / Google TV";
    if (r.svcUUID.indexOf("ffe0") >= 0) return "BLE IoT Module";
    if (r.svcUUID.indexOf("60910001") >= 0) return "Smart Home Device";
  }
  // By vendor ID
  if (r.mfrVid == 0x0006) return "Windows Device";
  if (r.mfrVid == 0x0075) return "Samsung Phone/TV";
  if (r.mfrVid == 0x00E0) return "Android / Google Device";
  if (r.mfrVid == 0x01D8) return "Tile Tracker";
  if (r.mfrVid == 0x02E5) return "Fitbit";
  if (r.mfrVid == 0x0837) return "OPPO / OnePlus Phone";
  if (r.mfrVid == 0x0310) return "ESP32 Device";
  // Embedded IP = smart home
  if (r.embeddedIP.length()) return "Smart Home / IoT Device (IP: " + r.embeddedIP + ")";
  // OUI-based
  const char* oui = ouiLookup(r.mac);
  if (oui) return String(oui) + " Device";
  // PUBLIC mac usually = fixed device
  if (r.isPublic) return "Fixed BLE Device (not mobile)";
  return "Unknown BLE Device";
}

// ═══════════════════════════════════════════════════════════
//  RSSI SIGNAL QUALITY + DISTANCE ESTIMATE
// ═══════════════════════════════════════════════════════════
const char* quality(int r) {
  if (r >= -60) return "Excellent";
  if (r >= -70) return "Good";
  if (r >= -80) return "Fair";
  if (r >= -90) return "Weak";
  return "Poor";
}

String distEstimate(int rssi, int8_t txPwr, bool hasTx) {
  if (!hasTx) txPwr = -59;   // assume standard 0 dBm Tx at 1m
  float ratio  = (txPwr - rssi) / 20.0;
  float dist   = pow(10.0, ratio);
  char buf[24];
  if      (dist < 1.0)  snprintf(buf, sizeof(buf), "<1m");
  else if (dist < 5.0)  snprintf(buf, sizeof(buf), "~%.0fm", dist);
  else if (dist < 20.0) snprintf(buf, sizeof(buf), "~%.0fm", dist);
  else                  snprintf(buf, sizeof(buf), ">20m");
  return String(buf);
}

// ═══════════════════════════════════════════════════════════
//  EMBEDDED IP DETECTOR (in manufacturer data)
// ═══════════════════════════════════════════════════════════
String detectEmbeddedIP(const String& mfrHex) {
  // Parse hex string back to bytes and look for private IP patterns
  // e.g. "37 08 C0 A8 3D 74 4F..." → C0 A8 = 192.168
  String result = "";
  if (mfrHex.length() < 11) return result;

  // Convert hex string to byte array
  uint8_t bytes[32]; int blen = 0;
  char tmp[4];
  for (int i = 0; i < (int)mfrHex.length() - 1 && blen < 32; i += 3) {
    tmp[0] = mfrHex[i]; tmp[1] = mfrHex[i+1]; tmp[2] = 0;
    bytes[blen++] = (uint8_t)strtol(tmp, nullptr, 16);
  }

  for (int i = 0; i <= blen - 4; i++) {
    bool is192 = (bytes[i]==192 && bytes[i+1]==168);
    bool is10  = (bytes[i]==10);
    bool is172 = (bytes[i]==172 && bytes[i+1]>=16 && bytes[i+1]<=31);
    if (is192 || is10 || is172) {
      char ip[20];
      snprintf(ip, sizeof(ip), "%d.%d.%d.%d",
        bytes[i], bytes[i+1], bytes[i+2], bytes[i+3]);
      result = String(ip);
      break;
    }
  }
  return result;
}

// ═══════════════════════════════════════════════════════════
//  GATT NAME RESOLUTION
// ═══════════════════════════════════════════════════════════
String gattReadName(const char* macStr) {
  BLEAddress addr(macStr);
  BLEClient* client = BLEDevice::createClient();
  client->setMTU(23);
  String result = "";

  if (!client->connect(addr)) {
    client->disconnect();
    delete client;
    return "";
  }

  BLERemoteService* svc = nullptr;
  try { svc = client->getService(BLEUUID((uint16_t)0x1800)); }
  catch (...) {}

  if (svc) {
    BLERemoteCharacteristic* ch = nullptr;
    try { ch = svc->getCharacteristic(BLEUUID((uint16_t)0x2A00)); }
    catch (...) {}
    if (ch && ch->canRead()) {
      String val = ch->readValue().c_str();
      if (val.length() > 0) result = val;
    }
  }
  client->disconnect();
  delete client;
  return result;
}

// ═══════════════════════════════════════════════════════════
//  SCAN CALLBACK — store only, no Serial (prevents crash)
// ═══════════════════════════════════════════════════════════
class ScanCB : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice dev) {
    if (recCount >= MAX_DEVS) return;

    BLERecord& r    = recs[recCount++];
    r.mac           = dev.getAddress().toString().c_str();
    r.name          = dev.getName().length() ? dev.getName().c_str() : "";
    r.isPublic      = (dev.getAddress().getType() == BLE_ADDR_TYPE_PUBLIC);
    r.connectable   = dev.isConnectable();
    r.rssi          = dev.getRSSI();
    r.hasTxPower    = dev.haveTXPower();
    r.txPower       = dev.haveTXPower() ? dev.getTXPower() : -59;
    r.svcUUID       = dev.haveServiceUUID() ? dev.getServiceUUID().toString().c_str() : "";
    r.mfrHex        = "";
    r.mfrVid        = 0;
    r.appleType     = 0;
    r.hasAppearance = dev.haveAppearance();
    r.appearance    = dev.haveAppearance() ? dev.getAppearance() : 0;
    r.embeddedIP    = "";

    if (dev.haveManufacturerData()) {
      String md = dev.getManufacturerData();
      char buf[4];
      for (int i = 0; i < (int)md.length(); i++) {
        snprintf(buf, sizeof(buf), "%02X ", (uint8_t)md[i]);
        r.mfrHex += buf;
      }
      if (md.length() >= 2) {
        r.mfrVid = (uint8_t)md[0] | ((uint8_t)md[1] << 8);
        if (r.mfrVid == 0x004C && md.length() >= 3)
          r.appleType = (uint8_t)md[2];
      }
      r.embeddedIP = detectEmbeddedIP(r.mfrHex);
    }
  }
};

// ═══════════════════════════════════════════════════════════
//  PRINT ONE DEVICE RECORD
// ═══════════════════════════════════════════════════════════
void printRecord(BLERecord& r, int idx) {
  String dtype = guessDeviceType(r);

  // Header
  Serial.printf("\n  [%02d] %s", idx + 1, r.mac.c_str());
  if (r.name.length())
    Serial.printf("  \"%s\"", r.name.c_str());
  Serial.println();

  // Device type
  Serial.printf("       Type     : %s\n", dtype.c_str());

  // Signal
  Serial.printf("       RSSI     : %d dBm  [%s]  Dist: %s\n",
    r.rssi, quality(r.rssi),
    distEstimate(r.rssi, r.txPower, r.hasTxPower).c_str());

  // Address
  Serial.printf("       AddrType : %s",
    r.isPublic ? "PUBLIC" : "RANDOM (privacy)");
  if (!r.isPublic) {
    const char* oui = ouiLookup(r.mac);
    if (oui) Serial.printf("  OUI: %s", oui);
  }
  Serial.println();

  // Connectable
  Serial.printf("       Connect  : %s\n",
    r.connectable ? "YES" : "NO");

  // Service UUID
  if (r.svcUUID.length()) {
    const char* svcName = decodeSvcUUID(r.svcUUID);
    if (svcName)
      Serial.printf("       SvcUUID  : %s  [%s]\n", r.svcUUID.c_str(), svcName);
    else
      Serial.printf("       SvcUUID  : %s\n", r.svcUUID.c_str());
  }

  // Manufacturer data
  if (r.mfrHex.length()) {
    Serial.printf("       MfrData  : %s\n", r.mfrHex.c_str());
    if (r.mfrVid == 0x004C) {
      Serial.printf("       Apple    : %s  (frame: 0x%02X)\n",
        appleFrame(r.appleType), r.appleType);
    } else {
      const char* vn = vendorName(r.mfrVid);
      Serial.printf("       Vendor   : %s  (ID: 0x%04X)\n",
        vn ? vn : "Unknown", r.mfrVid);
    }
    if (r.embeddedIP.length())
      Serial.printf("       EmbedIP  : %s  ← device IP in advertisement!\n",
        r.embeddedIP.c_str());
  }

  // Appearance
  if (r.hasAppearance)
    Serial.printf("       Appear   : 0x%04X\n", r.appearance);

  // TX Power
  if (r.hasTxPower)
    Serial.printf("       TxPower  : %d dBm\n", r.txPower);
}

// ═══════════════════════════════════════════════════════════
//  SETUP
// ═══════════════════════════════════════════════════════════
void setup() {
  Serial.begin(115200);
  delay(500);

  BLEDevice::init("ESP32_Lab");
  BLEDevice::setMTU(23);

  BLEScan* pScan = BLEDevice::getScan();
  pScan->setAdvertisedDeviceCallbacks(new ScanCB());
  pScan->setActiveScan(true);
  pScan->setInterval(45);
  pScan->setWindow(15);

  Serial.println("\n╔══════════════════════════════════════════════════════╗");
  Serial.println("║     ESP32 BLE Advanced Scanner — Final Version      ║");
  Serial.println("║     KLS GIT Belagavi — IoT Security Lab             ║");
  Serial.println("╚══════════════════════════════════════════════════════╝");
  Serial.println("\n  TIP: Power on BT headphones/speaker for named device");
  Serial.println("       Android → Settings → Bluetooth → Discoverable\n");
}

// ═══════════════════════════════════════════════════════════
//  MAIN LOOP
// ═══════════════════════════════════════════════════════════
int scanNum = 0;

void loop() {
  scanNum++;
  recCount = 0;

  Serial.printf("\n╔══════════════════════ Scan #%02d ══════════════════════╗\n", scanNum);
  Serial.printf( "║  Scanning %d seconds...                               ║\n", SCAN_DURATION);
  Serial.println("╚═══════════════════════════════════════════════════════╝\n");

  BLEDevice::getScan()->start(SCAN_DURATION, false);

  // ── Phase 1: Print all devices ────────────────────────────────────────
  for (int i = 0; i < recCount; i++) {
    printRecord(recs[i], i);
    trackDevice(recs[i].mac, recs[i].name, recs[i].rssi, scanNum);
  }

  // ── Phase 2: GATT name resolution for unnamed connectable PUBLIC devs ─
  int resolved = 0;
  bool anyPublicUnnamed = false;

  for (int i = 0; i < recCount; i++) {
    if (recs[i].name.length() == 0 &&
        recs[i].isPublic &&
        recs[i].connectable &&
        recs[i].mfrVid != 0x004C) {
      anyPublicUnnamed = true;
      break;
    }
  }

  if (anyPublicUnnamed) {
    Serial.println("\n  [GATT] Resolving names for unnamed public devices...");
    for (int i = 0; i < recCount; i++) {
      if (recs[i].name.length() == 0 &&
          recs[i].isPublic &&
          recs[i].connectable &&
          recs[i].mfrVid != 0x004C) {

        Serial.printf("  [GATT] %s ... ", recs[i].mac.c_str());
        String fetched = gattReadName(recs[i].mac.c_str());
        if (fetched.length()) {
          recs[i].name = fetched;
          Serial.printf("Name: \"%s\"\n", fetched.c_str());
          resolved++;
          // update tracker
          for (int j = 0; j < trackedCount; j++) {
            if (tracked[j].mac == recs[i].mac) {
              tracked[j].name = fetched; break;
            }
          }
        } else {
          Serial.println("no name / refused");
        }
        delay(300);
      }
    }
  }

  // ── Summary ───────────────────────────────────────────────────────────
  int named = 0, hidden = 0, publicCnt = 0, appleCnt = 0, androidCnt = 0, iotCnt = 0;
  for (int i = 0; i < recCount; i++) {
    if (recs[i].name.length()) named++;
    else hidden++;
    if (recs[i].isPublic) publicCnt++;
    if (recs[i].mfrVid == 0x004C) appleCnt++;
    String t = guessDeviceType(recs[i]);
    if (t.indexOf("Android") >= 0 || t.indexOf("Google") >= 0) androidCnt++;
    if (t.indexOf("IoT") >= 0 || t.indexOf("Smart Home") >= 0 ||
        t.indexOf("ESP32") >= 0 || t.indexOf("Sensor") >= 0) iotCnt++;
  }

  Serial.println("\n  ┌─────────────────── SUMMARY ───────────────────────┐");
  Serial.printf( "  │  Total devices     : %-4d                          │\n", recCount);
  Serial.printf( "  │  Named             : %-4d                          │\n", named);
  Serial.printf( "  │  Hidden (privacy)  : %-4d                          │\n", hidden);
  Serial.printf( "  │  Apple devices     : %-4d                          │\n", appleCnt);
  Serial.printf( "  │  Android/Google    : %-4d                          │\n", androidCnt);
  Serial.printf( "  │  IoT/Smart Home    : %-4d                          │\n", iotCnt);
  Serial.printf( "  │  Public MAC        : %-4d                          │\n", publicCnt);
  Serial.printf( "  │  GATT resolved     : %-4d                          │\n", resolved);
  Serial.printf( "  │  Total tracked     : %-4d  (all scans)             │\n", trackedCount);
  Serial.println("  └───────────────────────────────────────────────────┘");

  // Named devices list
  if (named > 0) {
    Serial.println("\n  ★ Named devices this scan:");
    for (int i = 0; i < recCount; i++) {
      if (recs[i].name.length())
        Serial.printf("    • %-22s  %s  %d dBm  [%s]\n",
          recs[i].name.c_str(), recs[i].mac.c_str(),
          recs[i].rssi, quality(recs[i].rssi));
    }
  }

  // Persistent devices (seen 3+ times)
  int persistent = 0;
  for (int i = 0; i < trackedCount; i++)
    if (tracked[i].seenCount >= 3) persistent++;

  if (persistent > 0 && scanNum >= 3) {
    Serial.println("\n  ⚑ Persistent devices (seen 3+ scans = likely fixed/installed):");
    for (int i = 0; i < trackedCount; i++) {
      if (tracked[i].seenCount >= 3) {
        Serial.printf("    • %s  seen:%d  RSSI:%d dBm",
          tracked[i].mac.c_str(), tracked[i].seenCount, tracked[i].lastRssi);
        if (tracked[i].name.length())
          Serial.printf("  \"%s\"", tracked[i].name.c_str());
        Serial.println();
      }
    }
  }

  BLEDevice::getScan()->clearResults();
  Serial.printf("\n  Next scan in %d sec...\n", SCAN_INTERVAL / 1000);
  delay(SCAN_INTERVAL);
}
