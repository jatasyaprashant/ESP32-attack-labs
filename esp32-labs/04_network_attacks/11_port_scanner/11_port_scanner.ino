/*
 * ESP32 IoT Port Scanner
 * Category: Network Attacks
 *
 * TCP connect scan across 16 IoT-critical ports: MQTT, CoAP,
 * Modbus, OPC-UA, MongoDB, Redis, Elasticsearch, BACnet.
 * Grabs service banners on open ports.
 *
 * Board  : ESP32 DevKit V1
 * Library: WiFi.h, WiFiClient.h (built-in)
 * KLS GIT Belagavi — IoT Security Lab | Authorized use only.
 */
#include <WiFi.h>
#include <WiFiClient.h>

#define WIFI_SSID  "YourWiFi"
#define WIFI_PASS  "YourPassword"
#define TARGET_IP  "192.168.1.1"

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
  Serial.printf("\n[*] IoT Port Scan -> %s (%d ports)\n\n",TARGET_IP,CNT);
  Serial.println(" PORT  | SERVICE       | STATE  | BANNER");
  Serial.println("-------+---------------+--------+----------------------------");
  for(int i=0;i<CNT;i++){
    WiFiClient c; c.setTimeout(600);
    Serial.printf("%5d  | %-13s | ",PORTS[i].n,PORTS[i].svc);
    if(c.connect(TARGET_IP,PORTS[i].n)){
      Serial.print("OPEN   | "); delay(300);
      if(c.available()){
        String b=c.readStringUntil('\n'); b.trim();
        if(b.length()>44) b=b.substring(0,44)+"...";
        Serial.print(b);
      } else Serial.print("(no banner)");
      c.stop();
    } else Serial.print("closed |");
    Serial.println(); delay(100);
  }
  Serial.println("\n[*] Scan complete.");
}
void loop(){}
