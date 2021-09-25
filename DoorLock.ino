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

struct Hex {
  char const* begin;
  size_t size;
};
void serial_print1(auto&& arg) {
  if constexpr (std::is_same_v<std::decay_t<decltype(arg)>, Hex>) {
    for (char c : std::string_view{arg.begin, arg.size}) {
      Serial.print((c >> 4) & 0xf, HEX);
      Serial.print((c >> 0) & 0xf, HEX);
    }
  } else if constexpr (std::is_same_v<std::decay_t<decltype(arg)>, std::string_view>) {
    Serial.write(arg.data(), arg.size());
  } else {
    Serial.print(arg);
  }
}
void serial_print(auto&& ... args) {
  (serial_print1(FWD(args)), ...);
}
void serial_println(auto&& ... args) {
  serial_print(FWD(args)...);
  Serial.println();
}

// WiFiClient client;
BearSSL::WiFiClientSecure client;

struct FatalError: public std::exception {
};
void fatal [[noreturn]] (auto ... args) {
  show_leds(CRGB::White);
  serial_println(FWD(args)...);
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
size_t wait_available() {
  while (true) {
    auto result = (client.*available)();
    if (result > 0) {
      return result;
    }
    yield();
    client_check();
  }
}

using SendBuffer = std::array<char, 1024>;
SendBuffer send_buffer;
SendBuffer::iterator send_end;

void ldap_send(auto const& message) {
  send_end = send_buffer.begin();
  struct {
    void write(char c) {
      write({&c, 1});
    }
    void write(std::string_view bytes) {
      if (send_buffer.end() < send_end + bytes.size()) {
        fatal("Send buffer overflow");
      }
      std::memcpy(send_end, bytes.data(), bytes.size());
      send_end += bytes.size();
    }
  } writer;
  message.write(writer);

  serial_println("> Sending LDAP message:");
  for (SendBuffer::iterator it = send_buffer.begin(); it != send_end;) {
    size_t available = wait_available<&decltype(client)::availableForWrite>();
    available = std::min(available, size_t(send_end - it));

    auto written = client.write(reinterpret_cast<uint8_t const*>(it), available);
    serial_print(Hex{it, written});
    it += written;
  }
  serial_println();
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
      if (parser_target > receive_buffer.end()) {
        fatal("Receive buffer overflow");
      }

      while (parser_end < parser_target) {
        size_t available = wait_available<&decltype(client)::available>();
        available = std::min(available, size_t(receive_buffer.end() - parser_end));

        auto read = client.read(reinterpret_cast<uint8_t*>(parser_end), available);
        serial_print(Hex{parser_end, read});
        parser_end += read;
      }

      auto result = std::string_view(parser_begin, length);
      parser_begin = parser_target;
      return result;
    }
  } reader;

  auto message = LDAP::message.read(reader);
  if (!message) {
    fatal("Expected LDAP message");
  }

  auto [message_id, protocol_op, controls_opt] = *message;
  if (message_id != expected_message_id) {
    fatal("Expected message id ", expected_message_id, " != ", message_id);
  }

  if (controls_opt) {
    serial_println("Got controls");
    auto controls = *controls_opt;
    while (!controls.empty()) {
      auto control = LDAP::control.read(controls);
      if (!control) {
        fatal("Expected control");
      }
      auto [control_type, criticality, control_value] = *control;
      serial_print("Control ", control_type, " ", criticality);
      if (control_value) {
        serial_print(" ", *control_value);
      }
      serial_println();
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
    fatal("Expected bind response ", int(protocol_op.tag_number));
  }
  auto [result_code, matched_dn, diagnostic_message, referral] = protocol_op.get<LDAP::ProtocolOp::BindResponse>();
  if (result_code != LDAP::ResultCode::Success) {
    fatal("Expected bind response success ", int(result_code));
  }
}

// Search for a LDAP user with the scanned badge NUID
void ldap_search(std::string_view badgenuid) {
  auto message_id = 2;

  // TODO: add a filter for ptl-active group
  serial_println("sending data to server");
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
      fatal("Expected search response ", int(protocol_op.tag_number));
    case LDAP::ProtocolOp::SearchResultEntry: {
      auto [object_name, attributes] = protocol_op.get<LDAP::ProtocolOp::SearchResultEntry>();
      serial_println("Object name ", object_name);
      while (!attributes.empty()) {
        auto partial_attribute = LDAP::partial_attribute.read(attributes);
        if (!partial_attribute) {
          fatal("Expected partial attribute");
        }
        auto [type, vals] = *partial_attribute;
        serial_println("Attribute type ", type);
        while (!vals.empty()) {
          auto val = LDAP::attribute_value.read(vals);
          if (!val) {
            fatal("Expected attribute value");
          }
          serial_println("Attribute value ", *val);
        }
      }
      continue;
    }
    case LDAP::ProtocolOp::SearchResultDone: {
      auto [result_code, matched_dn, diagnostic_message, referral] = protocol_op.get<LDAP::ProtocolOp::BindResponse>();
      if (result_code != LDAP::ResultCode::Success) {
        fatal("Expected search response success ", int(result_code));
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
    serial_println("Badge NUID: ", badgenuid);

    ldap_search(badgenuid);
    if (false) {

      // TODO: badge not found
      continue;

    }

    show_leds(CRGB::Green);
    serial_println("Unlocking");
    digitalWrite(RELAY_PIN, HIGH);
    delay(2000);
    digitalWrite(RELAY_PIN, LOW);
  }

}

void loop_with_wifi() {
  while (true) {

    serial_println("connecting to ", LDAP_HOSTNAME, ':', LDAP_PORT);
    if (!client.connect(LDAP_HOSTNAME, LDAP_PORT)) {
      serial_println("connection failed");
      wifi_check();
      continue;
    }

    serial_println("connected");
    try {
      loop_with_client();
    } catch (ClientError&) {
    }

    show_leds(CRGB::Purple);
    serial_println("disconnected");

  }
}

void setup() {
  Serial.begin(115200);
  serial_println();

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
  serial_println("Connecting to ", WIFI_SSID);

  while (WiFi.status() != WL_CONNECTED) {
    yield();
  }

  serial_println("WiFi connected, IP: ", WiFi.localIP());

  try {
    loop_with_wifi();
  } catch (WiFiError&) {
  }

  show_leds(CRGB::Purple);
  serial_println("WiFi disconnected");
}
