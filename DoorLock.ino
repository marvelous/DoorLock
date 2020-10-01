#include "LDAP_lib.hpp"

#include <sstream>
#include <ESP8266WiFi.h>
#include <SPI.h>
#include <MFRC522.h>

#define RST_PIN D4
#define SS_PIN D2
#define RELAY_PIN D1
MFRC522 mfrc522(SS_PIN, RST_PIN);

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

  // Init the SPI for the RFID reader
  SPI.begin();
	mfrc522.PCD_Init();
  pinMode(RELAY_PIN, OUTPUT);

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("");
  Serial.println("WiFi connected");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());
}

void loop() {
  // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
	if (!mfrc522.PICC_IsNewCardPresent()) {
		return;
	}

	// Read the cards, restart the loop on error
	if (!mfrc522.PICC_ReadCardSerial()) {
		return;
	}
  
  uint32_t badgenuid = 0;
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    badgenuid += mfrc522.uid.uidByte[i] << ((mfrc522.uid.size - i - 1) * 8);
	}
  // Convert the int to string
  string badgenuidstr;
  ostringstream badgenuidss;
  badgenuidss << badgenuid;
  badgenuidstr = badgenuidss.str();
  Serial.print("Badge NUID: ");
  Serial.println(badgenuidstr.c_str());

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
  while (client.available()) {
    char ch = static_cast<char>(client.read());
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
    client.write((const uint8_t*)req.c_str(), req.length());
  } else {
    client.stop();
    delay(2000);
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
  while (client.available()) {
    char ch = static_cast<char>(client.read());
    res += ch;
    Serial.print(ch, HEX);
  }
  Serial.println();

  // Close the connection
  client.stop();

  if (res.length() > 40) {
    digitalWrite(RELAY_PIN, HIGH);
    delay(2000);
    digitalWrite(RELAY_PIN, LOW);
  } else {
    delay(5000);
  }

  delay(1000);
}
