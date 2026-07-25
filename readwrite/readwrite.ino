/*
 * ESP32 + MFRC522 - Combined Read/Write with Serial Menu
 *
 * IMPORTANT FIX FROM PREVIOUS VERSION:
 *   PCD_PerformSelfTest() was removed from the init path. That routine
 *   loads special test values into the RC522's internal timer/FIFO
 *   registers, and on most boards PCD_Init() alone does NOT fully restore
 *   them afterward - it needs a real power cycle. That is why every
 *   authentication attempt started timing out 100% of the time, even on
 *   first try, right after self test ran. If you want to run self test,
 *   do it as a ONE-OFF sanity check in a separate sketch, power-cycle the
 *   board afterward, then flash your real program.
 *
 * USAGE:
 *   Open Serial Monitor at 115200 baud, 'No line ending' or 'Newline' ok.
 *   Type 1 + Enter  -> WRITE mode (writes a message you type to block 4)
 *   Type 2 + Enter  -> READ mode (reads and prints block 4)
 *   Then present a card when prompted.
 *
 * IF AUTH STILL TIMES OUT INTERMITTENTLY (not 100% of the time):
 *   That points back to power - power RC522 VCC from a dedicated 3.3V
 *   regulator (not ESP32's onboard 3V3 pin) and add a 100uF + 100nF
 *   capacitor pair across RC522 VCC/GND, as close to the module as
 *   possible. Keep all SPI wires under ~10cm.
 */

#include <SPI.h>
#include <MFRC522.h>

#define SS_PIN   5
#define RST_PIN  21

MFRC522 mfrc522(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key;

byte keyBytes[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const byte BLOCK = 4; // avoid block 0 (manufacturer) and sector trailers (3,7,11...)

enum Mode { MODE_NONE, MODE_READ, MODE_WRITE };
Mode currentMode = MODE_NONE;
String writeBuffer = "";

void setup() {
  Serial.begin(115200);
  while (!Serial);
  delay(200);

  SPI.begin();
  mfrc522.PCD_Init();
  mfrc522.PCD_SetAntennaGain(mfrc522.RxGain_max);
  hardReset();

  for (byte i = 0; i < 6; i++) key.keyByte[i] = keyBytes[i];

  Serial.println(F("=== MFRC522 Read/Write ==="));
  mfrc522.PCD_DumpVersionToSerial();
  printMenu();
}

void printMenu() {
  Serial.println();
  Serial.println(F("Select mode:"));
  Serial.println(F("  1 = WRITE to card"));
  Serial.println(F("  2 = READ from card"));
  Serial.print(F("> "));
}

void hardReset() {
  digitalWrite(RST_PIN, LOW);
  delay(50);
  digitalWrite(RST_PIN, HIGH);
  delay(50);
  mfrc522.PCD_Init();
  mfrc522.PCD_AntennaOn();
  delay(50);
}

void loop() {
  handleMenuInput();

  if (currentMode == MODE_NONE) {
    delay(50);
    return;
  }

  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    delay(50);
    return;
  }

  Serial.print(F("Card UID: "));
  printHex(mfrc522.uid.uidByte, mfrc522.uid.size);
  Serial.println();

  if (!authenticate(BLOCK)) {
    Serial.println(F("Authentication failed. See notes at top of file if this happens every single time."));
  } else if (currentMode == MODE_WRITE) {
    doWrite(BLOCK);
  } else if (currentMode == MODE_READ) {
    doRead(BLOCK);
  }

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  currentMode = MODE_NONE;
  printMenu();
}

void handleMenuInput() {
  if (Serial.available() == 0) return;

  char c = Serial.read();
  while (Serial.available()) Serial.read(); // flush rest of line

  if (c == '1') {
    currentMode = MODE_WRITE;
    Serial.println(F("WRITE mode. Type the text to store (max 16 chars), then Enter:"));
    writeBuffer = readLineBlocking();
    Serial.println(F("Present the card now..."));
  } else if (c == '2') {
    currentMode = MODE_READ;
    Serial.println(F("READ mode. Present the card now..."));
  }
}

String readLineBlocking() {
  String s = "";
  while (true) {
    if (Serial.available()) {
      char ch = Serial.read();
      if (ch == '\n' || ch == '\r') {
        if (s.length() > 0) break;
      } else {
        s += ch;
      }
    }
  }
  return s;
}

bool authenticate(byte block) {
  const int maxRetries = 3;
  for (int attempt = 1; attempt <= maxRetries; attempt++) {
    MFRC522::StatusCode status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &mfrc522.uid);
    if (status == MFRC522::STATUS_OK) return true;

    Serial.print(F("Auth attempt "));
    Serial.print(attempt);
    Serial.print(F(" failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));

    if (attempt < maxRetries) {
      hardReset();
      delay(100);
      mfrc522.PICC_ReadCardSerial();
    }
  }
  return false;
}

void doRead(byte block) {
  byte buffer[18];
  byte size = sizeof(buffer);
  MFRC522::StatusCode status = (MFRC522::StatusCode) mfrc522.MIFARE_Read(block, buffer, &size);

  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Read failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }

  Serial.print(F("Block "));
  Serial.print(block);
  Serial.print(F(" data: "));
  for (byte i = 0; i < 16; i++) {
    if (buffer[i] >= 32 && buffer[i] <= 126) Serial.print((char)buffer[i]);
    else Serial.print('.');
  }
  Serial.println();

  Serial.print(F("Raw hex: "));
  printHex(buffer, 16);
  Serial.println();
}

void doWrite(byte block) {
  byte dataBlock[16];
  memset(dataBlock, 0x00, sizeof(dataBlock));
  for (unsigned int i = 0; i < writeBuffer.length() && i < 16; i++) {
    dataBlock[i] = (byte) writeBuffer[i];
  }

  MFRC522::StatusCode status = (MFRC522::StatusCode) mfrc522.MIFARE_Write(block, dataBlock, 16);

  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Write failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }

  Serial.println(F("Write successful. Verifying..."));
  doRead(block);
}

void printHex(byte *buffer, byte bufferSize) {
  for (byte i = 0; i < bufferSize; i++) {
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.print(buffer[i], HEX);
  }
}
