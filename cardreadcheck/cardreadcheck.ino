#include <SPI.h>
#include <MFRC522.h>

#define SS_PIN 5
#define RST_PIN 21

MFRC522 mfrc522(SS_PIN, RST_PIN);

MFRC522::MIFARE_Key key;

void setup() {
  Serial.begin(115200);

  SPI.begin(18, 19, 23, 5);
  mfrc522.PCD_Init();

  // Default MIFARE Classic key = FF FF FF FF FF FF
  for (byte i = 0; i < 6; i++)
    key.keyByte[i] = 0xFF;

  Serial.println("Place MIFARE Classic card...");
}

void loop() {

  if (!mfrc522.PICC_IsNewCardPresent())
    return;

  if (!mfrc522.PICC_ReadCardSerial())
    return;

  byte block = 4;
  byte buffer[18];
  byte size = sizeof(buffer);

  MFRC522::StatusCode status;

  status = mfrc522.PCD_Authenticate(
      MFRC522::PICC_CMD_MF_AUTH_KEY_A,
      block,
      &key,
      &(mfrc522.uid)
  );

  if (status != MFRC522::STATUS_OK) {
    Serial.print("Authentication failed: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }

  status = mfrc522.MIFARE_Read(block, buffer, &size);

  if (status != MFRC522::STATUS_OK) {
    Serial.print("Read failed: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
  } else {

    Serial.println("\nBlock 4 Data:");

    for (byte i = 0; i < 16; i++) {
      Serial.print(buffer[i], HEX);
      Serial.print(" ");
    }

    Serial.println("\nASCII:");

    for (byte i = 0; i < 16; i++) {
      if (buffer[i] >= 32 && buffer[i] <= 126)
        Serial.print((char)buffer[i]);
      else
        Serial.print(".");
    }

    Serial.println();
  }

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();

  delay(1500);
}