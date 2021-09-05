#include "ptldap/ldap.hpp"

#include <ESP8266WiFi.h>
#include <SPI.h>
#include <MFRC522.h>
#include <FastLED.h>
#include <ESPAsyncTCP.h>
#include <coroutine>

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

AsyncClient client;

void ldap_send(auto const& message) {
  Serial.println("> LDAP message:");

  struct {
    void write(char c) {
      write({&c, 1});
    }
    void write(std::string_view bytes) {
      serial_print_hex(bytes);
      client.write(bytes.data(), bytes.size());
    }
  } writer;
  // TODO: check buffer overflow behavior, maybe buffer here
  message.write(writer);

  Serial.println();
}
auto ldap_receive() {
  return std::optional<bool>{}; // TODO
}

struct Timer {

  size_t remaining = 0;

  void reset(auto remaining) {
    this->remaining = remaining;
  }
  bool done() {
    if (remaining) {
      --remaining;
    }
    return remaining == 0;
  }

};

template<typename Callbacks>
struct Service {

  enum class State {
    INACTIVE, ACTIVATING, ACTIVE,
  } state = State::INACTIVE;

  Callbacks callbacks;

  void deactivate() {
    callbacks.inactive();
    state = State::INACTIVE;
  }

  bool activate() {
    if (!callbacks.check_condition()) {
      if (state != State::INACTIVE) {
        deactivate();
      }
      return false;
    }

    switch (state) {
    case State::INACTIVE:
      callbacks.activating();
      state = State::ACTIVATING;
    case State::ACTIVATING:
      if (!callbacks.check_activating()) {
        return false;
      }
      callbacks.active();
      state = State::ACTIVE;
      return true;
    case State::ACTIVE:
      if (callbacks.check_active()) {
        return true;
      }
      deactivate();
      return false;
    }
  }

};

struct WifiCallbacks {
  bool check_condition() {
    return true;
  }
  void activating() {
    show_leds(CRGB::Purple);
    Serial.print("Connecting to WiFi...");
  }
  bool check_activating() {
    return WiFi.status() == WL_CONNECTED;
  }
  void active() {
    Serial.print("WiFi connected, IP: ");
    Serial.println(WiFi.localIP());
  }
  bool check_active() {
    return WiFi.status() == WL_CONNECTED;
  }
  void inactive() {
  }
};
Service<WifiCallbacks> wifi_service;
auto wifi_task = []()->std::string{co_yield 0;}();

struct ClientCallbacks {
  bool check_condition() {
    return wifi_service.activate();
  }
  void activating() {
    show_leds(CRGB::Blue);
    Serial.print("connecting to ");
    Serial.print(LDAP_HOSTNAME);
    Serial.print(':');
    Serial.println(LDAP_PORT);
    client.connect(LDAP_HOSTNAME, LDAP_PORT);
  }
  bool check_activating() {
    return client.connected();
  }
  void active() {
    Serial.println("connected");
  }
  bool check_active() {
    return client.connected();
  }
  void inactive() {
    client.stop();
  }
};
Service<ClientCallbacks> client_service;

struct BindCallbacks {
  bool check_condition() {
    return client_service.activate();
  }
  void activating() {
    show_leds(CRGB::Purple);
    ldap_send(LDAP::message(1, LDAP::bind_request(1, LDAP_LOGIN, LDAP::authentication_choice.make<LDAP::AuthenticationChoice::Simple>(LDAP_PASSWORD)), std::nullopt));
  }
  bool check_activating() {
    auto message = ldap_receive();
    if (!message) {
      return false;
    }
    // TODO: check result
    return true;
  }
  void active() {
  }
  bool check_active() {
    return true;
  }
  void inactive() {
  }
};
Service<BindCallbacks> bind_service;

std::string badgenuid;
struct BadgeCallbacks {
  bool check_condition() {
    return true;
  }
  void activating() {
  }
  bool check_activating() {
    return mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial();
  }
  void active() {
    badgenuid.reserve(mfrc522.uid.size);
    for (byte b : mfrc522.uid.uidByte) {
      badgenuid.push_back(b);
      if (badgenuid.size() == mfrc522.uid.size) {
        break;
      }
    }

    Serial.print("Badge NUID: ");
    serial_print_hex(badgenuid);
    Serial.println();
  }
  bool check_active() {
    return true;
  }
  void inactive() {
    badgenuid.clear();
  }
};
Service<BadgeCallbacks> badge_service;

struct SearchCallbacks {
  bool check_condition() {
    return bind_service.activate() && badge_service.activate();
  }
  void activating() {
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
          std::string_view(badgenuid),
          std::nullopt
        ),
        LDAP::attribute_selection("cn"sv)
      ),
      std::nullopt
    ));
  }
  bool check_activating() {
    auto message = ldap_receive();
    if (!message) {
      return false;
    }
    // TODO: check result
    return true;
  }
  void active() {
  }
  bool check_active() {
    return true;
  }
  void inactive() {
  }
};
Service<SearchCallbacks> search_service;

Timer door_timer;
struct DoorCallbacks {
  bool check_condition() {
    return search_service.activate();
  }
  void activating() {
    show_leds(CRGB::Green);
    Serial.println("Unlocking");
    digitalWrite(RELAY_PIN, HIGH);
    door_timer.reset(2000);
  }
  bool check_activating() {
    return door_timer.done();
  }
  void active() {
    digitalWrite(RELAY_PIN, LOW);
    show_leds(CRGB::Red);
    badge_service.deactivate();
  }
  bool check_active() {
    return true;
  }
  void inactive() {
  }
};
Service<DoorCallbacks> door_service;

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

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
}

void loop() {
  door_service.activate();
}
