#include "ptldap/ldap.hpp"

#include <ESP8266WiFi.h>
#include <SPI.h>
#include <MFRC522.h>
#include <FastLED.h>

#define RST_PIN D4
#define SS_PIN D8
#define RELAY_PIN D1
MFRC522 mfrc522(SS_PIN, RST_PIN);

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

struct FatalError: public std::exception {
};
void fatal [[noreturn]] () {
  show_leds(CRGB::White);
  throw FatalError();
}

struct WiFiError: public std::exception {
};
void wifi_check() {
  if (WiFi.status() != WL_CONNECTED) {
    throw WiFiError();
  }
}

struct ClientError: public std::exception {
};
void client_check() {
  wifi_check();
  if (!client.connected()) {
    throw ClientError();
  }
}

template<auto available>
size_t wait_available(auto& client) {
  while (true) {
    auto result = (client.*available)();
    if (result > 0) {
      return result;
    }
    yield();
    client_check();
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

auto ldap_receive(auto expected_message_id) {
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

  auto message = LDAP::message.read(reader);
  if (!message) {
    Serial.println("Expected LDAP message");
    fatal();
  }

  auto [message_id, protocol_op, controls_opt] = *message;
  if (message_id != expected_message_id) {
    Serial.print("Expected message id ");
    Serial.print(expected_message_id);
    Serial.print(" != ");
    Serial.println(message_id);
    fatal();
  }

  if (controls_opt) {
    Serial.println("Got controls");
    auto controls = *controls_opt;
    while (!controls.empty()) {
      auto control = LDAP::control.read(controls);
      if (!control) {
        Serial.println("Expected control");
        fatal();
      }
      auto [control_type, criticality, control_value] = *control;
      Serial.print("Control ");
      Serial.write(control_type.data(), control_type.size());
      Serial.print(" ");
      Serial.print(criticality);
      if (control_value) {
        Serial.print(" ");
        Serial.write(control_value->data(), control_value->size());
      }
      Serial.println();
    }
  }

  return protocol_op;
}

void ldap_bind() {
  auto message_id = 1;

  ldap_send(
    LDAP::message(
      message_id,
      LDAP::bind_request(
        1,
        LDAP_LOGIN,
        LDAP::authentication_choice.make<LDAP::AuthenticationChoice::Simple>(
          LDAP_PASSWORD
        )
      ),
      std::nullopt
    )
  );

  auto protocol_op = ldap_receive(message_id);
  if (protocol_op.tag_number != LDAP::ProtocolOp::BindResponse) {
    Serial.print("Expected bind response ");
    Serial.println(int(protocol_op.tag_number));
    fatal();
  }
  auto [result_code, matched_dn, diagnostic_message, referral] = protocol_op.get<LDAP::ProtocolOp::BindResponse>();
  if (result_code != LDAP::ResultCode::Success) {
    Serial.print("Expected bind response success ");
    Serial.println(int(result_code));
    fatal();
  }
}

// Search for a LDAP user with the scanned badge NUID
void ldap_search(std::string_view badgenuid) {
  auto message_id = 2;

  // TODO: add a filter for ptl-active group
  Serial.println("sending data to server");
  ldap_send(
    LDAP::message(
      message_id,
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
    )
  );

  while (true) {
    auto protocol_op = ldap_receive(message_id);
    switch (protocol_op.tag_number) {
    default:
      Serial.print("Expected search response ");
      Serial.println(int(protocol_op.tag_number));
      fatal();
    case LDAP::ProtocolOp::SearchResultEntry: {
      auto [object_name, attributes] = protocol_op.get<LDAP::ProtocolOp::SearchResultEntry>();
      Serial.print("Object name ");
      Serial.write(object_name.data(), object_name.size());
      Serial.println();
      while (!attributes.empty()) {
        auto partial_attribute = LDAP::partial_attribute.read(attributes);
        if (!partial_attribute) {
          Serial.println("Expected partial attribute");
          fatal();
        }
        auto [type, vals] = *partial_attribute;
        Serial.print("Attribute type ");
        Serial.write(type.data(), type.size());
        Serial.println();
        while (!vals.empty()) {
          auto val = LDAP::attribute_value.read(vals);
          if (!val) {
            Serial.println("Expected attribute value");
            return;
          }
          Serial.print("Attribute value ");
          Serial.write(val->data(), val->size());
          Serial.println();
        }
      }
      continue;
    }
    case LDAP::ProtocolOp::SearchResultDone: {
      auto [result_code, matched_dn, diagnostic_message, referral] = protocol_op.get<LDAP::ProtocolOp::BindResponse>();
      if (result_code != LDAP::ResultCode::Success) {
        Serial.print("Expected search response success ");
        Serial.println(int(result_code));
        fatal();
      }
      return;
    }
    }
  }
}

void loop_with_client() {

  parser_begin = receive_buffer.begin();
  parser_end = receive_buffer.begin();
  ldap_bind();

  while (true) {
    show_leds(CRGB::Blue);
    while (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
      yield();
      client_check();
    }

    auto badgenuid = std::string_view(reinterpret_cast<char*>(mfrc522.uid.uidByte), mfrc522.uid.size);
    Serial.print("Badge NUID: ");
    serial_print_hex(badgenuid);
    Serial.println();

    ldap_search(badgenuid);
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

void loop_with_wifi() {
  while (true) {

    Serial.print("connecting to ");
    Serial.print(LDAP_HOSTNAME);
    Serial.print(':');
    Serial.println(LDAP_PORT);
    if (!client.connect(LDAP_HOSTNAME, LDAP_PORT)) {
      Serial.println("connection failed");
      wifi_check();
      continue;
    }

    Serial.println("connected");
    try {
      loop_with_client();
    } catch (ClientError&) {
    }

    show_leds(CRGB::Purple);
    Serial.println("disconnected");

  }
}

void setup() {
  Serial.begin(115200);
  Serial.println();

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
}

void loop() {
  Serial.print("Connecting to ");
  Serial.println(WIFI_SSID);

  while (WiFi.status() != WL_CONNECTED) {
    yield();
  }

  Serial.print("WiFi connected, IP: ");
  Serial.println(WiFi.localIP());

  try {
    loop_with_wifi();
  } catch (WiFiError&) {
  }

  show_leds(CRGB::Purple);
  Serial.println("WiFi disconnected");
}
