/*
 * ESP32 I2C Bus Scanner
 * Category: Hardware Security
 *
 * Probes all 127 I2C addresses to discover connected chips.
 * Identifies EEPROMs, IMU sensors, OLED displays, RTC modules,
 * ADCs, and environmental sensors by their I2C address.
 * Default: SDA=GPIO21, SCL=GPIO22.
 *
 * Board  : ESP32 DevKit V1
 * Library: Wire.h (built-in)
 * KLS GIT Belagavi — IoT Security Lab | Authorized use only.
 */
#include <Wire.h>

struct Dev{uint8_t a;const char* n;};
Dev KNOWN[]={
  {0x20,"PCF8574 I/O Expander"}, {0x27,"PCF8574 LCD Backpack"},
  {0x3C,"SSD1306 OLED"},         {0x3D,"SSD1306 OLED (alt)"},
  {0x48,"ADS1115 ADC"},          {0x50,"AT24C32 EEPROM"},
  {0x51,"AT24Cxx EEPROM"},       {0x52,"AT24Cxx EEPROM"},
  {0x53,"ADXL345 Accelerometer"},{0x57,"AT24Cxx EEPROM"},
  {0x68,"MPU-6050 / DS3231 RTC"},{0x69,"MPU-6050 (alt)"},
  {0x76,"BME280 / BMP280"},      {0x77,"BME680 (alt)"},
  {0x23,"BH1750 Light Sensor"},  {0x29,"VL53L0X ToF"},
};
const int NK=16;

const char* identify(uint8_t a){
  for(int i=0;i<NK;i++) if(KNOWN[i].a==a) return KNOWN[i].n;
  return "Unknown device";
}

void setup(){
  Serial.begin(115200);
  Wire.begin(21,22); Wire.setClock(100000); delay(1000);
  Serial.println("[*] I2C Bus Scanner  SDA=GPIO21  SCL=GPIO22");
  Serial.println("=============================================");
  int found=0;
  for(uint8_t a=1;a<127;a++){
    Wire.beginTransmission(a);
    uint8_t e=Wire.endTransmission();
    if(e==0){found++;Serial.printf("[+] 0x%02X -> %s\n",a,identify(a));}
    else if(e==4){Serial.printf("[!] 0x%02X -> Bus error\n",a);}
    delay(5);
  }
  Serial.printf("\n[*] Found %d device(s)\n",found);
}
void loop(){}
