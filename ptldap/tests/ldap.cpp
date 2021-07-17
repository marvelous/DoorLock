#include "../ldap.hpp"

#include <sstream>

#define CATCH_CONFIG_FAST_COMPILE
#include "catch.hpp"

using namespace std;

TEST_CASE("LDAP::DelRequest") {

    // From https://ldap.com/ldapv3-wire-protocol-reference-ldap-message/
    auto bytes = "\x30\x35\x02\x01\x05\x4a\x11\x64\x63\x3d\x65\x78\x61\x6d\x70\x6c\x65\x2c\x64\x63\x3d\x63\x6f\x6d\xa0\x1d\x30\x1b\x04\x16\x31\x2e\x32\x2e\x38\x34\x30\x2e\x31\x31\x33\x35\x35\x36\x2e\x31\x2e\x34\x2e\x38\x30\x35\x01\x01\xff"sv;
    auto reader = LDAP::make_reader(BER::make_reader(Bytes::StringViewReader{bytes}));

    auto message = TRY(reader.read_message());
    CHECK(message.message_id == 0x05);
    CHECK(message.identifier.is_tag_number(LDAP::TagNumber::DelRequest));

    auto del_request = TRY(message.read_del_request());
    CHECK(del_request.dn == "dc=example,dc=com"sv);

    auto controls = TRY(message.read_controls());
    auto control = TRY(controls.read_control());
    CHECK(control.control_type == "1.2.840.113556.1.4.805"sv);
    CHECK(control.criticality == true);
    CHECK(control.control_value == nullopt);

    CHECK(controls.ber.bytes.empty());
    CHECK(message.ber.bytes.empty());
    CHECK(reader.ber.bytes.empty());

    auto writer = LDAP::make_writer(BER::make_writer(Bytes::StringWriter()));
    writer.write_message(0x05, LDAP::DelRequest{"dc=example,dc=com"sv}, LDAP::Control{"1.2.840.113556.1.4.805"sv, true});
    CHECK(writer.ber.bytes.string == bytes);

};

TEST_CASE("LDAP::BindRequest") {

    // https://ldap.com/ldapv3-wire-protocol-reference-bind/
    auto bytes = "\x30\x39\x02\x01\x01\x60\x34\x02\x01\x03\x04\x24\x75\x69\x64\x3d\x6a\x64\x6f\x65\x2c\x6f\x75\x3d\x50\x65\x6f\x70\x6c\x65\x2c\x64\x63\x3d\x65\x78\x61\x6d\x70\x6c\x65\x2c\x64\x63\x3d\x63\x6f\x6d\x80\x09\x73\x65\x63\x72\x65\x74\x31\x32\x33"sv;
    auto reader = LDAP::make_reader(BER::make_reader(Bytes::StringViewReader{bytes}));

    auto message = TRY(reader.read_message());
    CHECK(message.message_id == 0x01);
    CHECK(message.identifier.is_tag_number(LDAP::TagNumber::BindRequest));

    auto bind_request = TRY(message.read_bind_request());
    CHECK(bind_request.version == 3);
    CHECK(bind_request.name == "uid=jdoe,ou=People,dc=example,dc=com"sv);

    auto password = TRY(bind_request.read_simple());
    CHECK(password == "secret123"sv);

    CHECK(bind_request.ber.bytes.empty());
    CHECK(message.ber.bytes.empty());
    CHECK(reader.ber.bytes.empty());

    auto writer = LDAP::make_writer(BER::make_writer(Bytes::StringWriter()));
    writer.write_message(0x01, LDAP::BindRequest<LDAP::Authentication::Simple>{3, "uid=jdoe,ou=People,dc=example,dc=com"sv, {"secret123"sv}});
    CHECK(writer.ber.bytes.string == bytes);

};
