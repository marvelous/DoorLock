#include "../ldap.hpp"

#include <sstream>

#define CATCH_CONFIG_FAST_COMPILE
#include "catch.hpp"

using namespace std;

// TEST_CASE("LDAP::DelRequest") {

//     // From https://ldap.com/ldapv3-wire-protocol-reference-ldap-message/
//     auto bytes = "\x30\x35\x02\x01\x05\x4a\x11\x64\x63\x3d\x65\x78\x61\x6d\x70\x6c\x65\x2c\x64\x63\x3d\x63\x6f\x6d\xa0\x1d\x30\x1b\x04\x16\x31\x2e\x32\x2e\x38\x34\x30\x2e\x31\x31\x33\x35\x35\x36\x2e\x31\x2e\x34\x2e\x38\x30\x35\x01\x01\xff"sv;

//     auto writer = BER::Writer(Bytes::StringWriter());
//     LDAP::Message(0x05, LDAP::ProtocolOp(LDAP::DelRequest("dc=example,dc=com"sv)), LDAP::Controls{LDAP::Control("1.2.840.113556.1.4.805"sv, true, std::nullopt)}).write(writer);
//     CHECK(writer.bytes.string == bytes);

//     auto reader = BER::Reader(Bytes::StringViewReader{bytes});

//     auto [message_id, protocol_op, controls_opt] = TRY(reader.read<LDAP::Message>());
//     CHECK(message_id == 0x05);
//     CHECK(protocol_op.tag_number == LDAP::TagNumber::DelRequest);

//     auto del_request = TRY(protocol_op.template read<LDAP::DelRequest>());
//     CHECK(del_request == "dc=example,dc=com"sv);

//     auto controls = TRY(controls_opt);
//     auto [control_type, criticality, control_value] = TRY(controls.read());
//     CHECK(control_type == "1.2.840.113556.1.4.805"sv);
//     CHECK(criticality == true);
//     CHECK(control_value == nullopt);

//     // CHECK(controls.bytes.empty());
//     // CHECK(message.bytes.empty());
//     // CHECK(reader.bytes.empty());

// };

TEST_CASE("LDAP::BindRequest") {

    // https://ldap.com/ldapv3-wire-protocol-reference-bind/
    auto bytes = "\x30\x39\x02\x01\x01\x60\x34\x02\x01\x03\x04\x24\x75\x69\x64\x3d\x6a\x64\x6f\x65\x2c\x6f\x75\x3d\x50\x65\x6f\x70\x6c\x65\x2c\x64\x63\x3d\x65\x78\x61\x6d\x70\x6c\x65\x2c\x64\x63\x3d\x63\x6f\x6d\x80\x09\x73\x65\x63\x72\x65\x74\x31\x32\x33"sv;

    auto writer = BER::Writer(Bytes::StringWriter());
    // writer.write(LDAP::message_id(42));
    // writer.write(LDAP::authentication_choice_simple("secret123"sv));
    // LDAP::bind_request(3, "uid=jdoe,ou=People,dc=example,dc=com"sv, LDAP::authentication_choice_simple("secret123"sv));
    // LDAP::message(0x01, LDAP::bind_request(3, "uid=jdoe,ou=People,dc=example,dc=com"sv, LDAP::authentication_choice_simple("secret123"sv)), std::nullopt);
    // LDAP::control("1.2.840.113556.1.4.805"sv, true, std::nullopt);
    // writer.write(LDAP::control("1.2.840.113556.1.4.805"sv, true, std::nullopt));
    // LDAP::controls(LDAP::control("1.2.840.113556.1.4.805"sv, true, std::nullopt));
    writer.write(LDAP::controls(LDAP::control("1.2.840.113556.1.4.805"sv, true, std::nullopt)));
    // LDAP::message(0x01, LDAP::bind_request(3, "uid=jdoe,ou=People,dc=example,dc=com"sv, LDAP::authentication_choice_simple("secret123"sv)), LDAP::controls(LDAP::control("1.2.840.113556.1.4.805"sv, true, std::nullopt)));
    // writer.write(LDAP::message(0x01, LDAP::bind_request(3, "uid=jdoe,ou=People,dc=example,dc=com"sv, LDAP::authentication_choice_simple("secret123"sv)), LDAP::controls(LDAP::control("1.2.840.113556.1.4.805"sv, true, std::nullopt))));
    CHECK(writer.bytes.string == bytes);

};

// TEST_CASE("LDAP::SearchRequest") {

//     // https://ldap.com/ldapv3-wire-protocol-reference-search/
//     auto bytes = "\x30\x56\x02\x01\x02\x63\x51\x04\x11\x64\x63\x3d\x65\x78\x61\x6d\x70\x6c\x65\x2c\x64\x63\x3d\x63\x6f\x6d\x0a\x01\x02\x0a\x01\x00\x02\x02\x03\xe8\x02\x01\x1e\x01\x01\x00\xa0\x24\xa3\x15\x04\x0b\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73\x04\x06\x70\x65\x72\x73\x6f\x6e\xa3\x0b\x04\x03\x75\x69\x64\x04\x04\x6a\x64\x6f\x65\x30\x06\x04\x01\x2a\x04\x01\x2b"sv;

//     auto writer = LDAP::Writer(BER::Writer(Bytes::StringWriter()));
//     writer.write_message(0x02, LDAP::SearchRequest<int>{"dc=example,dc=com"sv, LDAP::Scope::WholeSubtree, LDAP::DerefAliases::NeverDerefAliases, 1000, 30, false, LDAP::Filter::and_(LDAP::Filter::equalityMatch("objectClass"sv, "person"sv), LDAP::Filter::equalityMatch("uid"sv, "joe"sv)), {"*"sv, "+"sv}});
//     // for (auto i = 0; i < std::min(bytes.size(), writer.ber.bytes.string.size()); ++i) {
//     //     printf("%02x %02x\n", uint8_t(bytes[i]), uint8_t(writer.ber.bytes.string[i]));
//     // }
//     // CHECK(writer.ber.bytes.string == bytes);

// };
