#include "ptldap/ldap.hpp"

#include <ESP8266WiFi.h>
#include <SPI.h>
#include <MFRC522.h>
#include <FastLED.h>
#include <ESPAsyncTCP.h>
#include <cont.h>

#define RST_PIN D4
#define SS_PIN D8
#define RELAY_PIN D1
MFRC522 mfrc522(SS_PIN, RST_PIN);

// TODO: choose state colors
std::array<CRGB, 1> leds;
void show_leds(auto ... leds) {
  ::leds = {leds...};
  FastLED.show();
}

// This file is in .gitignore
// You can disallow anonymous access to the badge ID so people can't be impersonated
// It should contain the following values:
/*
#define WIFI_SSID "WIFI_SSID"
#define WIFI_PASSWORD "WIFI_PSK"
#define LDAP_HOSTNAME "ldap.posttenebraslab.ch"
#define LDAP_PORT LDAP_PORT
#define LDAP_LOGIN "cn=DoorLockCN,ou=DoorLockOU,dc=DoorLockDC"
#define LDAP_PASSWORD "DOORLOCK_LDAP_PASSWD"
#define LDAP_GROUP "ou=Members,dc=DoorLockDC"
*/
#include "config.h"

using std::literals::string_view_literals::operator""sv;

void serial_print_hex(char c) {
  Serial.print((c >> 4) & 0xf, HEX);
  Serial.print((c >> 0) & 0xf, HEX);
}
void serial_print_hex(auto const& string) {
  for (char c : string) {
    serial_print_hex(c);
  }
}

// WiFiClient client;
BearSSL::WiFiClientSecure client;

cont_t main_cont;

template<auto available>
size_t wait_available(auto& client) {
  while (true) {
    auto result = (client.*available)();
    if (result > 0) {
      return result;
    }
    cont_yield(&main_cont);
  }
}

void ldap_send(auto const& message) {
  Serial.println("> Sending LDAP message:");

  struct {
    void write(char c) {
      write({&c, 1});
    }
    void write(std::string_view bytes) {
      while (!bytes.empty()) {
        size_t available = wait_available<&decltype(client)::availableForWrite>(client);
        available = std::min(available, bytes.size());

        auto written = client.write(reinterpret_cast<uint8_t const*>(bytes.data()), available);
        serial_print_hex(bytes.substr(0, written));
        bytes.remove_prefix(written);
      }
    }
  } writer;
  message.write(writer);

  Serial.println();
}

using ReceiveBuffer = std::array<char, 1024>;
ReceiveBuffer receive_buffer;
ReceiveBuffer::iterator parser_begin;
ReceiveBuffer::iterator parser_end;

auto ldap_receive() {
  // compact buffer
  auto begin = receive_buffer.begin();
  std::memmove(begin, parser_begin, parser_end - parser_begin);
  parser_begin = begin;

  struct {
    std::optional<uint8_t> read() {
      return OPT_TRY(read(1)).front();
    }
    std::optional<std::string_view> read(size_t length) {
      auto parser_target = parser_begin + length;
      OPT_REQUIRE(parser_target <= receive_buffer.end());

      while (parser_end < parser_target) {
        size_t available = wait_available<&decltype(client)::available>(client);
        available = std::min(available, size_t(receive_buffer.end() - parser_end));

        auto read = client.read(reinterpret_cast<uint8_t*>(parser_end), available);
        serial_print_hex(std::string_view(parser_end, read));
        parser_end += read;
      }

      auto result = std::string_view(parser_begin, length);
      parser_begin = parser_target;
      return result;
    }
  } reader;
  return LDAP::message.read(reader);
}

void main_task() {

  show_leds(CRGB::Purple);

  parser_begin = receive_buffer.begin();
  parser_end = receive_buffer.begin();
  ldap_send(LDAP::message(
    1,
    LDAP::bind_request(
      1,
      LDAP_LOGIN,
      LDAP::authentication_choice.make<LDAP::AuthenticationChoice::Simple>(
        LDAP_PASSWORD
      )
    ),
    std::nullopt
  ));
  auto message = ldap_receive();
  // TODO: check response message

  while (true) {
    show_leds(CRGB::Blue);
    while (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
      cont_yield(&main_cont);
    }

    auto badgenuid = std::string_view(reinterpret_cast<char*>(mfrc522.uid.uidByte), mfrc522.uid.size);
    Serial.print("Badge NUID: ");
    serial_print_hex(badgenuid);
    Serial.println();

    // Search for a LDAP user with the scanned badge NUID
    // TODO: add a filter for ptl-active group
    Serial.println("sending data to server");
    ldap_send(LDAP::message(
      2,
      LDAP::search_request(
        LDAP_GROUP,
        LDAP::SearchRequestScope::SingleLevel,
        LDAP::SearchRequestDerefAliases::NeverDerefAliases,
        0,
        0,
        false,
        LDAP::filter.make<LDAP::Filter::ExtensibleMatch>(
          std::nullopt,
          "badgenuid"sv,
          badgenuid,
          std::nullopt
        ),
        LDAP::attribute_selection("cn"sv)
      ),
      std::nullopt
    ));

    auto message = ldap_receive();
    // TODO: check response message
    if (false) {

      // TODO: badge not found
      continue;

    }

    show_leds(CRGB::Green);
    Serial.println("Unlocking");
    digitalWrite(RELAY_PIN, HIGH);
    delay(2000);
    digitalWrite(RELAY_PIN, LOW);

  }

}

cont_t client_cont;
void client_task() {
  while (true) {

    show_leds(CRGB::Purple);
    Serial.print("connecting to ");
    Serial.print(LDAP_HOSTNAME);
    Serial.print(':');
    Serial.println(LDAP_PORT);
    if (!client.connect(LDAP_HOSTNAME, LDAP_PORT)) {
      Serial.println("connection failed");
      continue;
    }

    while (!client.connected()) {
      cont_yield(&client_cont);
    }

    Serial.println("connected");
    cont_init(&main_cont);

    do {
      cont_run(&main_cont, main_task);
      cont_yield(&client_cont);
    } while (client.connected());

    Serial.println("disconnected");

  }
}

cont_t wifi_cont;
void wifi_task() {
  while (true) {

    show_leds(CRGB::Purple);
    Serial.println("Connecting to WiFi...");

    while (WiFi.status() != WL_CONNECTED) {
      cont_yield(&wifi_cont);
    }

    Serial.print("WiFi connected, IP: ");
    Serial.println(WiFi.localIP());
    cont_init(&client_cont);

    do {
      cont_run(&client_cont, client_task);
      cont_yield(&wifi_cont);
    } while (WiFi.status() == WL_CONNECTED);

    Serial.println("WiFi disconnected");

  }
}

void setup() {
  Serial.begin(115200);

  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(WIFI_SSID);

  // Wait a bit, can help when resetting or reflashing sometimes
  delay(1000);

  FastLED.addLeds<WS2812, D3, GRB>(leds.data(), leds.size());
  show_leds(CRGB::Purple);

  // Init the SPI for the RFID reader
  SPI.begin();
	mfrc522.PCD_Init();
  mfrc522.PCD_DumpVersionToSerial();
  pinMode(RELAY_PIN, OUTPUT);
  digitalWrite(RELAY_PIN, LOW);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  client.setInsecure();

  cont_init(&wifi_cont);
}

void loop() {
  cont_run(&wifi_cont, wifi_task);
}
