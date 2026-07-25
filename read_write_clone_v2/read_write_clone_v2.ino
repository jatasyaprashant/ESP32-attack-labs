/*
 * ESP32 + MFRC522 – Read / Write / Clone (Fixed Multi-Sector)
 * ============================================================
 * Menu:
 *   1 = Write text to block 4
 *   2 = Read text from block 4
 *   3 = Clone card – reads all 16 sectors from source, writes to destination
 *
 * ROOT CAUSE OF PREVIOUS CLONE FAILURE:
 *   After PCD_StopCrypto1() ends a sector session, the MIFARE card enters
 *   a protocol-error state if the reader immediately attempts auth on the
 *   next sector without first re-selecting the card.
 *   The card must be cycled through: HALT → WUPA → SELECT before each new
 *   sector authentication. WUPA (0x52) wakes cards from HALT state, unlike
 *   REQA (0x26) which only reaches IDLE-state cards.
 *   Without this, Sector 1 fails with "Error in communication" and every
 *   sector after that times out because the card stops responding entirely.
 *   Block 4 lives in Sector 1 – so it was never cloned even though READ
 *   mode (which only touches Sector 1) worked perfectly fine on its own.
 *
 * WHAT IS CLONED:
 *   ✔  All data blocks across all 16 sectors
 *   ✘  Block 0  – manufacturer UID, permanently read-only on real cards
 *   ✘  Sector trailers (3,7,11,...) – writing wrong access bits bricks card
 *
 * WIRING:
 *   RC522 SDA→GPIO5  SCK→GPIO18  MOSI→GPIO23
 *   MISO→GPIO19  RST→GPIO21  3.3V→3.3V  GND→GND
 */

#include <SPI.h>
#include <MFRC522.h>

// ── Pins ──────────────────────────────────────────────────────────────────
#define SS_PIN   5
#define RST_PIN  21

// ── MIFARE Classic 1K constants ───────────────────────────────────────────
#define TOTAL_SECTORS   16
#define BLOCKS_PER_SEC   4
#define TOTAL_BLOCKS    64    // 16 × 4
#define BLOCK_SIZE      16

// ── Hardware ──────────────────────────────────────────────────────────────
MFRC522 mfrc522(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key;

// ── Clone storage (64 × 16 = 1024 bytes) ─────────────────────────────────
byte clonedData[TOTAL_BLOCKS][BLOCK_SIZE];
bool blockRead[TOTAL_BLOCKS];
int  srcBlocksRead = 0;

// ── UID saved for inter-sector re-selection ───────────────────────────────
byte savedUID[10];
byte savedUIDLen = 0;

// ── Mode state machine ────────────────────────────────────────────────────
enum Mode { MODE_IDLE, MODE_READ, MODE_WRITE, MODE_CLONE_SRC, MODE_CLONE_DST };
Mode mode = MODE_IDLE;

String writeText   = "";
const byte SINGLE_BLOCK = 4;

// ══════════════════════════════════════════════════════════════════════════
void setup() {
  Serial.begin(115200);
  while (!Serial);
  delay(200);

  SPI.begin();
  mfrc522.PCD_Init();
  mfrc522.PCD_SetAntennaGain(mfrc522.RxGain_max);
  hardReset();

  for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF;

  Serial.println(F("\n=== MFRC522 Read / Write / Clone ==="));
  mfrc522.PCD_DumpVersionToSerial();
  printMenu();
}

// ══════════════════════════════════════════════════════════════════════════
void loop() {
  handleSerial();
  if (mode == MODE_IDLE) { delay(50); return; }

  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    delay(50);
    return;
  }

  Serial.print(F("\nCard UID: "));
  printHex(mfrc522.uid.uidByte, mfrc522.uid.size);
  Serial.println();

  switch (mode) {

    case MODE_READ:
      if (authenticateSingle(SINGLE_BLOCK)) readBlock(SINGLE_BLOCK);
      else Serial.println(F("Auth failed."));
      mfrc522.PICC_HaltA();
      mfrc522.PCD_StopCrypto1();
      printMenu();
      break;

    case MODE_WRITE:
      if (authenticateSingle(SINGLE_BLOCK)) writeBlock(SINGLE_BLOCK);
      else Serial.println(F("Auth failed."));
      mfrc522.PICC_HaltA();
      mfrc522.PCD_StopCrypto1();
      printMenu();
      break;

    case MODE_CLONE_SRC:
      cloneReadSource();
      // Card is already halted inside cloneReadSource
      if (srcBlocksRead > 0) {
        swapCardCountdown(5); // 5-second countdown to swap cards
        mode = MODE_CLONE_DST;
        Serial.println(F(">>> Present the EMPTY / DESTINATION card now..."));
      } else {
        Serial.println(F("Nothing read – clone aborted."));
        printMenu();
      }
      break;

    case MODE_CLONE_DST:
      cloneWriteDestination();
      // Card halted inside cloneWriteDestination
      printMenu();
      break;

    default: break;
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Serial menu
// ══════════════════════════════════════════════════════════════════════════
void handleSerial() {
  if (mode != MODE_IDLE || !Serial.available()) return;

  char c = Serial.read();
  flushSerial();

  if (c == '1') {
    Serial.println(F("\n[WRITE] Enter text (max 16 chars) then Enter:"));
    writeText = readLineBlocking(30000);
    if (writeText.length() == 0) { Serial.println(F("Nothing entered.")); printMenu(); return; }
    if (writeText.length() > 16) writeText = writeText.substring(0, 16);
    Serial.print(F("Will write: \"")); Serial.print(writeText); Serial.println(F("\""));
    Serial.println(F("Present card..."));
    mode = MODE_WRITE;

  } else if (c == '2') {
    Serial.println(F("\n[READ] Present card..."));
    mode = MODE_READ;

  } else if (c == '3') {
    memset(clonedData,  0x00,   sizeof(clonedData));
    memset(blockRead,   false,  sizeof(blockRead));
    srcBlocksRead = 0;
    mode = MODE_CLONE_SRC;
    Serial.println(F("\n[CLONE] Step 1 of 2 – Present SOURCE card..."));
  }
}

void printMenu() {
  mode = MODE_IDLE;
  Serial.println(F("\n─────────────────────────────"));
  Serial.println(F("  1  Write text to card"));
  Serial.println(F("  2  Read text from card"));
  Serial.println(F("  3  Clone card (source -> empty)"));
  Serial.println(F("─────────────────────────────"));
  Serial.print(F("> "));
}

// ══════════════════════════════════════════════════════════════════════════
// Hardware helpers
// ══════════════════════════════════════════════════════════════════════════
void hardReset() {
  digitalWrite(RST_PIN, LOW);  delay(50);
  digitalWrite(RST_PIN, HIGH); delay(50);
  mfrc522.PCD_Init();
  mfrc522.PCD_AntennaOn();
  delay(50);
}

// Store the currently selected card's UID so we can re-select it later
void saveCurrentUID() {
  savedUIDLen = mfrc522.uid.size;
  memcpy(savedUID, mfrc522.uid.uidByte, savedUIDLen);
}

/*
 * After PICC_HaltA() the card is in HALT state.
 * REQA (used by PICC_IsNewCardPresent) does NOT wake HALT-state cards.
 * WUPA (0x52) wakes both IDLE and HALT state cards.
 * We then do anti-collision + SELECT with the known UID to get back
 * to the ACTIVE state ready for the next sector authentication.
 */
bool reSelectCard() {
  delay(5);

  byte atqa[2];
  byte atqaSize = sizeof(atqa);

  // Wake from HALT using WUPA
  MFRC522::StatusCode ws = mfrc522.PICC_WakeupA(atqa, &atqaSize);
  if (ws != MFRC522::STATUS_OK && ws != MFRC522::STATUS_COLLISION) {
    return false;
  }

  // Restore saved UID then SELECT
  mfrc522.uid.size = savedUIDLen;
  memcpy(mfrc522.uid.uidByte, savedUID, savedUIDLen);
  mfrc522.uid.sak = 0x08; // MIFARE Classic 1K SAK

  MFRC522::StatusCode ss = mfrc522.PICC_Select(&mfrc522.uid);
  return (ss == MFRC522::STATUS_OK);
}

// ══════════════════════════════════════════════════════════════════════════
// Single-block auth with retry (for options 1 & 2)
// ══════════════════════════════════════════════════════════════════════════
bool authenticateSingle(byte block) {
  for (int attempt = 1; attempt <= 3; attempt++) {
    MFRC522::StatusCode s = (MFRC522::StatusCode)
      mfrc522.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &mfrc522.uid);
    if (s == MFRC522::STATUS_OK) return true;

    Serial.print(F("  Auth attempt ")); Serial.print(attempt);
    Serial.print(F(" failed: ")); Serial.println(mfrc522.GetStatusCodeName(s));

    if (attempt < 3) { hardReset(); delay(100); mfrc522.PICC_ReadCardSerial(); }
  }
  return false;
}

// ══════════════════════════════════════════════════════════════════════════
// Read / Write single block (options 1 & 2)
// ══════════════════════════════════════════════════════════════════════════
void readBlock(byte block) {
  byte buf[18]; byte sz = sizeof(buf);
  MFRC522::StatusCode s = (MFRC522::StatusCode) mfrc522.MIFARE_Read(block, buf, &sz);
  if (s != MFRC522::STATUS_OK) {
    Serial.print(F("Read failed: ")); Serial.println(mfrc522.GetStatusCodeName(s)); return;
  }
  Serial.print(F("Block ")); Serial.print(block); Serial.print(F(" text: "));
  for (byte i = 0; i < 16; i++)
    Serial.print((buf[i] >= 32 && buf[i] <= 126) ? (char)buf[i] : '.');
  Serial.print(F("\nBlock ")); Serial.print(block); Serial.print(F(" hex : "));
  printHex(buf, 16); Serial.println();
}

void writeBlock(byte block) {
  byte data[16]; memset(data, 0x00, 16);
  for (unsigned int i = 0; i < writeText.length() && i < 16; i++)
    data[i] = (byte)writeText[i];

  MFRC522::StatusCode s = (MFRC522::StatusCode) mfrc522.MIFARE_Write(block, data, 16);
  if (s != MFRC522::STATUS_OK) {
    Serial.print(F("Write failed: ")); Serial.println(mfrc522.GetStatusCodeName(s)); return;
  }
  Serial.println(F("Write OK – verifying..."));
  readBlock(block);
}

// ══════════════════════════════════════════════════════════════════════════
// CLONE – Step 1: read all sectors from SOURCE card
// ══════════════════════════════════════════════════════════════════════════
void cloneReadSource() {
  Serial.println(F("\n──── Reading SOURCE card ────"));
  saveCurrentUID(); // save UID for re-selection between sectors

  for (byte sector = 0; sector < TOTAL_SECTORS; sector++) {
    byte firstBlock = sector * BLOCKS_PER_SEC;

    // ── Re-select card before every sector (except the very first) ────────
    // After the previous sector we called PICC_HaltA(). The card is now in
    // HALT state. WUPA + SELECT brings it back to ACTIVE state so we can
    // authenticate the next sector.
    if (sector > 0) {
      if (!reSelectCard()) {
        Serial.print(F("Sector ")); Serial.print(sector);
        Serial.println(F(": re-select failed – skipping rest"));
        break; // card left field; no point continuing
      }
    }

    // ── Authenticate this sector ──────────────────────────────────────────
    MFRC522::StatusCode authSt = (MFRC522::StatusCode)
      mfrc522.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A, firstBlock, &key, &mfrc522.uid);

    if (authSt != MFRC522::STATUS_OK) {
      Serial.print(F("Sector ")); Serial.print(sector);
      Serial.print(F(" auth failed: "));
      Serial.println(mfrc522.GetStatusCodeName(authSt));
      mfrc522.PCD_StopCrypto1();
      mfrc522.PICC_HaltA(); // halt so next reSelectCard() works cleanly
      delay(10);
      continue;
    }

    // ── Read all blocks in this sector ────────────────────────────────────
    for (byte b = 0; b < BLOCKS_PER_SEC; b++) {
      byte blockAddr = firstBlock + b;

      if (blockAddr == 0) {
        Serial.println(F("Block  0: [skip – manufacturer, read-only]"));
        continue;
      }
      if (isSectorTrailer(blockAddr)) {
        Serial.print(F("Block ")); printBlockLabel(blockAddr);
        Serial.println(F(": [skip – sector trailer]"));
        continue;
      }

      byte buf[18]; byte sz = sizeof(buf);
      MFRC522::StatusCode rs =
        (MFRC522::StatusCode) mfrc522.MIFARE_Read(blockAddr, buf, &sz);

      Serial.print(F("Block ")); printBlockLabel(blockAddr); Serial.print(F(": "));
      if (rs == MFRC522::STATUS_OK) {
        memcpy(clonedData[blockAddr], buf, 16);
        blockRead[blockAddr] = true;
        srcBlocksRead++;
        printHex(clonedData[blockAddr], 16);
        Serial.println();
      } else {
        Serial.print(F("READ FAILED – "));
        Serial.println(mfrc522.GetStatusCodeName(rs));
      }
    }

    // ── End this sector session – halt so reSelectCard() works next time ──
    mfrc522.PCD_StopCrypto1();
    mfrc522.PICC_HaltA();
    delay(10);
  }

  Serial.println(F("──── Source read complete ────"));
  Serial.print(F("Blocks captured: ")); Serial.print(srcBlocksRead);
  Serial.println(F(" / 47 possible data blocks"));
  // 47 = sector0(blocks 1,2) + sectors1-15(3 each) = 2 + 45
}

// ══════════════════════════════════════════════════════════════════════════
// CLONE – Step 2: write all captured data to DESTINATION card
// ══════════════════════════════════════════════════════════════════════════
void cloneWriteDestination() {
  if (srcBlocksRead == 0) {
    Serial.println(F("No clone data available. Run option 3 again."));
    return;
  }

  Serial.println(F("\n──── Writing DESTINATION card ────"));
  saveCurrentUID(); // save destination card UID for re-selection

  int written = 0, failed = 0, skipped = 0;

  for (byte sector = 0; sector < TOTAL_SECTORS; sector++) {
    byte firstBlock = sector * BLOCKS_PER_SEC;

    // Re-select destination card before each sector (same as read side)
    if (sector > 0) {
      if (!reSelectCard()) {
        Serial.print(F("Sector ")); Serial.print(sector);
        Serial.println(F(": re-select failed – skipping rest"));
        skipped += 3;
        break;
      }
    }

    MFRC522::StatusCode authSt = (MFRC522::StatusCode)
      mfrc522.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A, firstBlock, &key, &mfrc522.uid);

    if (authSt != MFRC522::STATUS_OK) {
      Serial.print(F("Sector ")); Serial.print(sector);
      Serial.print(F(" auth failed: "));
      Serial.println(mfrc522.GetStatusCodeName(authSt));
      mfrc522.PCD_StopCrypto1();
      mfrc522.PICC_HaltA();
      skipped += 3;
      delay(10);
      continue;
    }

    for (byte b = 0; b < BLOCKS_PER_SEC; b++) {
      byte blockAddr = firstBlock + b;

      if (blockAddr == 0)            { skipped++; continue; }
      if (isSectorTrailer(blockAddr)){ continue; }
      if (!blockRead[blockAddr])     {
        Serial.print(F("Block ")); printBlockLabel(blockAddr);
        Serial.println(F(": no source data – skipped"));
        skipped++;
        continue;
      }

      MFRC522::StatusCode ws = (MFRC522::StatusCode)
        mfrc522.MIFARE_Write(blockAddr, clonedData[blockAddr], 16);

      Serial.print(F("Block ")); printBlockLabel(blockAddr); Serial.print(F(": "));
      if (ws == MFRC522::STATUS_OK) {
        written++;
        printHex(clonedData[blockAddr], 16);
        Serial.println(F("  OK"));
      } else {
        failed++;
        Serial.print(F("WRITE FAILED – "));
        Serial.println(mfrc522.GetStatusCodeName(ws));
      }
    }

    mfrc522.PCD_StopCrypto1();
    mfrc522.PICC_HaltA();
    delay(10);
  }

  // ── Summary ───────────────────────────────────────────────────────────
  Serial.println(F("\n═══════════════════════════════"));
  Serial.println(F("        CLONE SUMMARY"));
  Serial.println(F("═══════════════════════════════"));
  Serial.print(F("  Blocks written : ")); Serial.println(written);
  Serial.print(F("  Blocks failed  : ")); Serial.println(failed);
  Serial.print(F("  Blocks skipped : ")); Serial.println(skipped);
  Serial.println(F("  (block 0 + sector trailers always skipped)"));

  if (failed == 0 && written > 0)
    Serial.println(F("\n  Clone successful!"));
  else if (written > 0)
    Serial.println(F("\n  Partial clone – check failed blocks above."));
  else
    Serial.println(F("\n  Clone failed – no blocks written."));
  Serial.println(F("═══════════════════════════════"));
}

// ══════════════════════════════════════════════════════════════════════════
// Countdown between source read and destination write
// ══════════════════════════════════════════════════════════════════════════
void swapCardCountdown(int seconds) {
  Serial.println();
  Serial.println(F("══════════════════════════════════════"));
  Serial.println(F("  SOURCE card read complete!"));
  Serial.println(F("  REMOVE source card and place EMPTY card."));
  Serial.println(F("══════════════════════════════════════"));
  Serial.print(F("  Starting in: "));

  for (int i = seconds; i > 0; i--) {
    Serial.print(i);
    Serial.print(F("..."));
    delay(1000);
  }

  Serial.println(F("GO!"));
  Serial.println(F("══════════════════════════════════════"));
  Serial.println();
}

// ══════════════════════════════════════════════════════════════════════════
// Utility helpers
// ══════════════════════════════════════════════════════════════════════════
bool isSectorTrailer(byte block) { return ((block + 1) % BLOCKS_PER_SEC == 0); }

void printBlockLabel(byte block) { if (block < 10) Serial.print(' '); Serial.print(block); }

void printHex(byte *buf, byte len) {
  for (byte i = 0; i < len; i++) {
    Serial.print(buf[i] < 0x10 ? " 0" : " ");
    Serial.print(buf[i], HEX);
  }
}

void flushSerial() { while (Serial.available()) Serial.read(); }

String readLineBlocking(unsigned long timeoutMs) {
  String s = ""; unsigned long t = millis();
  while (millis() - t < timeoutMs) {
    if (Serial.available()) {
      char ch = Serial.read();
      if (ch == '\n' || ch == '\r') { if (s.length() > 0) break; }
      else s += ch;
    }
  }
  return s;
}
