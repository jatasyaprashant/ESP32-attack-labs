/*
 * ESP32 I2C EEPROM Hex Dumper
 * Category: Hardware Security
 *
 * Full hex + ASCII dump of AT24Cxx series I2C EEPROMs. Can
 * expose hardcoded WiFi credentials, API keys, certificates,
 * or device config stored in external non-volatile memory.
 * Default: AT24C32 (4 KB) at address 0x50.
 *
 * Board  : ESP32 DevKit V1
 * Library: Wire.h (built-in)
 * KLS GIT Belagavi — IoT Security Lab | Authorized use only.
 */
#include <Wire.h>

#define EEPROM_ADDR  0x50    // AT24C32 default — change if needed
#define EEPROM_SIZE  4096    // 4096 = AT24C32 | 32768 = AT24C256
#define SDA_PIN      21
#define SCL_PIN      22

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
  Serial.printf("[*] EEPROM Dump  0x%02X  %d bytes\n\n",EEPROM_ADDR,EEPROM_SIZE);
  Serial.println("         00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  |  ASCII");
  Serial.println("---------+-------------------------------+------------------+---------");
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
    Serial.printf(" |  %s\n",asc);
  }
  Serial.println("\n[*] Dump complete.");
}
void loop(){}
