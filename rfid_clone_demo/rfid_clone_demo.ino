/*
  ESP32 + RC522 — MIFARE Classic Clone Demo (teaching version)
  --------------------------------------------------------------
  Purpose: demonstrate, for a classroom, why MIFARE Classic cards
  are considered insecure: most cards in the wild still use the
  factory default key (FF FF FF FF FF FF) on every sector, which
  means anyone with a $3 reader can dump and rewrite the data.

  IMPORTANT TEACHING POINT:
  Block 0 of sector 0 contains the manufacturer UID. On a genuine
  MIFARE Classic card this block is factory write-locked — you
  CANNOT change a real card's UID. Full "UID cloning" only works
  with special rewritable ("magic"/CUID) cards, which use a
  non-standard unlock command not included here. This sketch
  clones the DATA (sectors 1+), not the UID, which is exactly
  what real fare-card/attendance-badge attacks exploit: the UID
  is often irrelevant, it's the *data* that's checked.

  Wiring (ESP32 VSPI):
    RC522 SDA/SS  -> GPIO 5
    RC522 SCK     -> GPIO 18
    RC522 MOSI    -> GPIO 23
    RC522 MISO    -> GPIO 19
    RC522 RST     -> GPIO 22
    RC522 3.3V    -> external 3.3V regulator (NOT the ESP32 board's 3V3 pin)
    RC522 GND     -> common ground with ESP32
    Add a 100nF ceramic cap across RC522 VCC/GND if you see random
    auth failures or garbled serial output — that's a power issue,
    not a code bug.
*/

#include <SPI.h>
#include <MFRC522.h>

#define SS_PIN  5
#define RST_PIN 22

MFRC522 rfid(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key;

const byte SECTORS = 16;      // MIFARE 1K = 16 sectors, 4 blocks each
byte dump[SECTORS * 4][16];
bool blockValid[SECTORS * 4];
bool haveDump = false;

void setup() {
  Serial.begin(115200);
  delay(300);
  SPI.begin(18, 19, 23, 5); // SCK, MISO, MOSI, SS
  rfid.PCD_Init();

  for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF; // factory default key

  Serial.println(F("\nESP32 RFID Clone Demo"));
  printMenu();
}

void loop() {
  if (Serial.available()) {
    String line = Serial.readStringUntil('\n');
    line.trim();
    if (line.length() > 0) {
      handleCommand(line.charAt(0));
      printMenu();
    }
  }
}

void printMenu() {
  Serial.println(F("\n===== Menu ====="));
  Serial.print(F("Dump in memory: "));
  Serial.println(haveDump ? "YES" : "no");
  Serial.println(F(" [1] Scan card (UID + type)"));
  Serial.println(F(" [2] Dump source card into memory"));
  Serial.println(F(" [3] Show dump"));
  Serial.println(F(" [4] Clone dump onto a target card"));
  Serial.println(F(" [5] Clear memory"));
  Serial.print(F("Select option: "));
}

void handleCommand(char cmd) {
  switch (cmd) {
    case '1': scanCard(); break;
    case '2': dumpSourceCard(); break;
    case '3': showDump(); break;
    case '4': cloneToTarget(); break;
    case '5': clearDump(); break;
    default: Serial.println(F("Invalid option."));
  }
}

// ---------- helpers ----------

bool waitForCard(unsigned long timeoutMs = 10000) {
  Serial.println(F("Waiting for card..."));
  unsigned long start = millis();
  while (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) {
    if (millis() - start > timeoutMs) {
      Serial.println(F("Timeout - no card detected."));
      return false;
    }
    delay(50);
  }
  return true;
}

void printUID(byte *uid, byte size) {
  for (byte i = 0; i < size; i++) {
    Serial.print(uid[i] < 0x10 ? "0" : "");
    Serial.print(uid[i], HEX);
    if (i < size - 1) Serial.print(":");
  }
  Serial.println();
}

void endSession() {
  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();
}

// ---------- commands ----------

void scanCard() {
  if (!waitForCard()) return;
  Serial.print(F("UID:  "));
  printUID(rfid.uid.uidByte, rfid.uid.size);
  Serial.print(F("Type: "));
  Serial.println(rfid.PICC_GetTypeName(rfid.PICC_GetType(rfid.uid.sak)));
  endSession();
}

void dumpSourceCard() {
  if (!waitForCard()) return;

  Serial.print(F("Source UID: "));
  printUID(rfid.uid.uidByte, rfid.uid.size);

  memset(blockValid, 0, sizeof(blockValid));
  byte ok = 0, failed = 0;

  for (byte sector = 0; sector < SECTORS; sector++) {
    byte trailer = sector * 4 + 3;
    MFRC522::StatusCode status = rfid.PCD_Authenticate(
      MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailer, &key, &(rfid.uid));

    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("Sector ")); Serial.print(sector);
      Serial.print(F(": auth failed ("));
      Serial.print(rfid.GetStatusCodeName(status));
      Serial.println(F(") - skipping"));
      failed += 4;
      continue;
    }

    for (byte offset = 0; offset < 4; offset++) {
      byte blockAddr = sector * 4 + offset;
      byte buffer[18];
      byte size = sizeof(buffer);
      status = rfid.MIFARE_Read(blockAddr, buffer, &size);
      if (status == MFRC522::STATUS_OK) {
        memcpy(dump[blockAddr], buffer, 16);
        blockValid[blockAddr] = true;
        ok++;
      } else {
        failed++;
      }
    }
  }

  endSession();
  haveDump = (ok > 0);
  Serial.print(F("Blocks read: ")); Serial.print(ok);
  Serial.print(F(", failed: ")); Serial.println(failed);

  if (failed == SECTORS * 4) {
    Serial.println(F("All sectors failed - check wiring/power to the RC522"));
    Serial.println(F("before assuming the key is wrong."));
  }
}

void showDump() {
  if (!haveDump) { Serial.println(F("No dump stored.")); return; }
  for (int i = 0; i < SECTORS * 4; i++) {
    if (!blockValid[i]) continue;
    Serial.print(F("Block "));
    if (i < 10) Serial.print(' ');
    Serial.print(i);
    Serial.print(F(": "));
    for (int j = 0; j < 16; j++) {
      Serial.print(dump[i][j] < 0x10 ? "0" : "");
      Serial.print(dump[i][j], HEX);
      Serial.print(' ');
    }
    Serial.println();
  }
}

void clearDump() {
  memset(dump, 0, sizeof(dump));
  memset(blockValid, 0, sizeof(blockValid));
  haveDump = false;
  Serial.println(F("Memory cleared."));
}

void cloneToTarget() {
  if (!haveDump) {
    Serial.println(F("No dump in memory. Run option 2 on the source card first."));
    return;
  }
  Serial.println(F("Present the BLANK/target card now."));
  if (!waitForCard()) return;

  Serial.print(F("Target UID: "));
  printUID(rfid.uid.uidByte, rfid.uid.size);
  Serial.println(F("This will overwrite data blocks on the target. Continue? (y/n)"));

  while (!Serial.available()) delay(10);
  String confirm = Serial.readStringUntil('\n');
  confirm.trim();
  if (!confirm.startsWith("y") && !confirm.startsWith("Y")) {
    Serial.println(F("Clone cancelled."));
    endSession();
    return;
  }

  byte written = 0, failed = 0;

  for (byte sector = 0; sector < SECTORS; sector++) {
    byte trailer = sector * 4 + 3;
    MFRC522::StatusCode status = rfid.PCD_Authenticate(
      MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailer, &key, &(rfid.uid));

    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("Sector ")); Serial.print(sector);
      Serial.println(F(": auth failed, skipping"));
      failed += 3;
      continue;
    }

    // Only write data blocks (offsets 0-2). Never write the trailer (offset 3)
    // here to avoid locking the sector with a bad key, and never write block 0
    // (the UID block) - that's read-only on a genuine card anyway.
    for (byte offset = 0; offset < 3; offset++) {
      byte blockAddr = sector * 4 + offset;
      if (blockAddr == 0) continue;
      if (!blockValid[blockAddr]) continue;

      status = rfid.MIFARE_Write(blockAddr, dump[blockAddr], 16);
      if (status == MFRC522::STATUS_OK) {
        written++;
      } else {
        Serial.print(F("Block ")); Serial.print(blockAddr);
        Serial.println(F(" write failed"));
        failed++;
      }
    }
  }

  endSession();
  Serial.print(F("Clone done. Blocks written: ")); Serial.print(written);
  Serial.print(F(", failed: ")); Serial.println(failed);
  Serial.println(F("Note: UID (block 0) was NOT changed - see header comment."));
}
