#include "ptldap/LDAP_lib.hpp"

#include <sstream>
#include <ESP8266WiFi.h>
#include <SPI.h>
#include <MFRC522.h>
#include <FastLED.h>

#define RST_PIN D4
#define SS_PIN D8
#define RELAY_PIN D1
MFRC522 mfrc522(SS_PIN, RST_PIN);

#define NUM_LEDS 1
CRGB leds[NUM_LEDS];

// This file is in .gitignore
// It should contain the following values:
/*
const char *ssid = "WIFI_SSID";
const char *password = "WIFI_PSK";
const char *host = "LDAP_HOST";
const uint16_t port = LDAP_PORT;
*/
#include "server.h"

// This file should contains the login for the LDAP
// You can disallow anonymous access to the badge ID people can't be imperssonated
// It should contain the following value:
/*
const char* ldap_login = "cn=DoorLockCN,ou=DoorLockOU,dc=DoorLockDC";
const char* ldap_passwd = "DOORLOCK_LDAP_PASSWD";
const char* ldap_member_group = "ou=Members,dc=DoorLockDC";
*/
#include "login.h"

void setup() {
  Serial.begin(115200);

  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(ssid);

  // Wait a bit, can help when resetting or reflashing some times
  delay(1000);

  FastLED.addLeds<WS2812, D3, GRB>(leds, NUM_LEDS);
  leds[0] = CRGB::Purple;
  FastLED.show();

  // Init the SPI for the RFID reader
  SPI.begin();
	mfrc522.PCD_Init();
  mfrc522.PCD_DumpVersionToSerial();
  pinMode(RELAY_PIN, OUTPUT);

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  Serial.print("Connecting to WiFi...");
  bool led_state = false;
  while (WiFi.status() != WL_CONNECTED) {
    if (led_state) {
      leds[0] = CRGB::Purple;
      FastLED.show();
    } else {
      leds[0] = CRGB::Black;
      FastLED.show();
    }
    delay(500);
    Serial.print(".");
    led_state = !led_state;
  }
  Serial.println("");

  Serial.print("WiFi connected, IP: ");
  Serial.println(WiFi.localIP());
}

void loop() {
  leds[0] = CRGB::Red;
  FastLED.show();

  // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
	if (!mfrc522.PICC_IsNewCardPresent()) {
    delay(100);
		return;
	}

	// Read the cards, restart the loop on error
	if (!mfrc522.PICC_ReadCardSerial()) {
		return;
	}

  leds[0] = CRGB::Blue;
  FastLED.show();

  // Save the badge NUID into a string
  Serial.print("Badge NUID: ");
  string badgenuidstr;
  ostringstream badgenuidss;
  for (char i = 0; i < mfrc522.uid.size; i++) {
    if (mfrc522.uid.uidByte[i] < 0x10) {
      Serial.print('0');
    }
    Serial.print(mfrc522.uid.uidByte[i], HEX);
    badgenuidss << (char) mfrc522.uid.uidByte[i];
	}
  Serial.println();
  badgenuidstr = badgenuidss.str();

  // Connect to the LDAP server
  Serial.print("connecting to ");
  Serial.print(host);
  Serial.print(':');
  Serial.println(port);

  // WiFiClient client;
  BearSSL::WiFiClientSecure client;
  client.setInsecure();
  if (!client.connect(host, port)) {
    Serial.println("connection failed");
    delay(500);
    return;
  }

  // This will send a string to the server
  Serial.println("Connecting to LDAP");
  if (client.connected()) {
    auto req = LDAP::BindRequest(ldap_login, ldap_passwd).str();
    Serial.println("> BindRequest");
    for(int i = 0; i < req.length(); i++) {
      if (req.c_str()[i] < 0x10) {
        Serial.print('0');
      }
      Serial.print(req.c_str()[i], HEX);
    }
    Serial.println();
    client.write((const uint8_t*)req.c_str(), req.length());
  } else {
    client.stop();
    delay(2000);
    return;
  }

  // Wait for data to be available
  unsigned long timeout = millis();
  while (client.available() == 0) {
    if (millis() - timeout > 5000) {
      Serial.println(">>> Client Timeout !");
      client.stop();
      return;
    }
  }

  // TODO: check if connection is accepted
  Serial.println("<BindResponse");
  while (client.available()) {
    char ch = static_cast<char>(client.read());
    if(ch < 0x10) {
      Serial.print('0');
    }
    Serial.print(ch, HEX);
  }
  Serial.println();

  // Search for a LDAP user with the scanned badge NUID
  // TODO: add a filter for ptl-active group
  Serial.println("sending data to server");
  if (client.connected()) {
    auto req = LDAP::SearchRequest(ldap_member_group,
                                   "badgenuid", 
                                   badgenuidstr,
                                   "cn").str();
    Serial.println(">SearchRequest");
    for(int i = 0; i < req.length(); i++) {
      if (req.c_str()[i] < 0x10) {
        Serial.print('0');
      }
      Serial.print(req.c_str()[i], HEX);
    }
    Serial.println();
    client.write((const uint8_t*)req.c_str(), req.length());
  } else {
    client.stop();
    delay(2000);
    Serial.println("Failed");
    return;
  }

  timeout = millis();
  while (client.available() == 0) {
    if (millis() - timeout > 5000) {
      Serial.println(">>> Client Timeout !");
      client.stop();
      return;
    }
  }

  // TODO: properly check if an user is found
  string res;
  Serial.println("<SearchResponse");
  while (client.available()) {
    char ch = static_cast<char>(client.read());
    res += ch;
    if(ch < 0x10) {
      Serial.print('0');
    }
    Serial.print(ch, HEX);
  }
  Serial.println();

  // Close the connection
  client.stop();

  if (res.length() > 40) {
    leds[0] = CRGB::Green;
    FastLED.show();
    Serial.println("Unlocking");
    digitalWrite(RELAY_PIN, HIGH);
    delay(2000);
    digitalWrite(RELAY_PIN, LOW);
    leds[0] = CRGB::Red;
    FastLED.show();
    Serial.println("Locking back");
  } else {
    for(int i = 0; i < 5; i++) {
      leds[0] = CRGB::Red;
      FastLED.show();
      delay(200);
      leds[0] = CRGB::Black;
      FastLED.show();
      delay(200);
    }
  }

  delay(1000);
}
