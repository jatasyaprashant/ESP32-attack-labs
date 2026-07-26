/*
 * ESP32 SPIFFS Flash Inspector
 * Category: Hardware Security
 *
 * Mounts the internal SPIFFS filesystem, lists all files with
 * size and ASCII content preview, then hunts for known sensitive
 * filenames (config, credentials, API keys, certificates).
 * Common attack surface in IoT firmware.
 *
 * Board  : ESP32 DevKit V1
 * Library: SPIFFS.h, FS.h (built-in ESP32 Arduino core)
 * KLS GIT Belagavi — IoT Security Lab | Authorized use only.
 */
#include <SPIFFS.h>
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
  Serial.printf("[*] SPIFFS  Total:%d  Used:%d  Free:%d bytes\n\n",
    SPIFFS.totalBytes(),SPIFFS.usedBytes(),
    SPIFFS.totalBytes()-SPIFFS.usedBytes());
  File root=SPIFFS.open("/"); File f=root.openNextFile();
  Serial.println("--- FILE LISTING ---");
  while(f){
    Serial.printf("[%7d B] /%s\n",f.size(),f.name());
    Serial.print("  Preview: ");
    int lim=min((size_t)80,(size_t)f.size());
    for(int i=0;i<lim;i++){char c=(char)f.read();Serial.print(isPrintable(c)?c:'.');}
    Serial.println();
    f=root.openNextFile();
  }
  root.close();
  Serial.println("\n--- SENSITIVE FILE SCAN ---");
  bool any=false;
  for(int i=0;i<SN;i++){
    if(SPIFFS.exists(SENSITIVE[i])){
      any=true;
      Serial.printf("\n[!!!] FOUND: %s\n",SENSITIVE[i]);
      File sf=SPIFFS.open(SENSITIVE[i]);
      Serial.println(sf.readString()); sf.close();
    }
  }
  if(!any) Serial.println("    No sensitive files detected.");
  Serial.println("\n[*] Done.");
}
void loop(){}
