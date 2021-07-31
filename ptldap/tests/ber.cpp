#include "../ber.hpp"

#include "catch.hpp"
#include "tools.hpp"

using namespace std;
using namespace BER;

auto identifier_write_read(auto&& bytes, auto&& encoding, auto&& tag_class, auto&& tag_number) {
    auto identifier = Identifier(encoding, tag_class, tag_number);

    auto writer = Bytes::StringWriter();
    identifier.write(writer);
    check_bytes(writer.string, bytes);

    auto reader = Bytes::StringViewReader{bytes};
    CHECK(TRY(decltype(identifier)::read(reader)) == identifier);
    check_bytes(reader.string, ""sv);
};

TEST_CASE("Identifier") {

    identifier_write_read("\x02"sv, Encoding::Primitive, TagClass::Universal, integer.identifier.tag_number);
    identifier_write_read("\x30"sv, Encoding::Constructed, TagClass::Universal, 0x10);
    identifier_write_read("\x7f\xde\xad\x42"sv, Encoding::Constructed, TagClass::Application, 0x1796c2);

}

void length_read(auto&& bytes, auto&& length) {
    auto reader = Bytes::StringViewReader{bytes};
    CHECK(TRY(Length::read(reader)).length == length);
    check_bytes(reader.string, ""sv);
};
void length_write_read(auto&& bytes, auto&& length) {
    auto writer = Bytes::StringWriter();
    Length(length).write(writer);
    check_bytes(writer.string, bytes);

    length_read(bytes, length);
};

TEST_CASE("Length") {

    SECTION("definite") {
        length_write_read("\x7f"sv, 0x7f);
        length_write_read("\x01"sv, 1);
        length_read("\x81\x01"sv, 1);
        length_write_read("\x81\xff"sv, 0xff);
        length_write_read("\x84\xff\xff\xff\xfe"sv, 0xfffffffe);
    }

    SECTION("overflow") {
        uint8_t header_size = 1;
        uint8_t data_length_size = 127;

        // Create a string with the first byte (0xff) standing for: long-form, 127 bytes for data length
        // And with 127 bytes of data length, all set to 255 (we are counting all particles in the galaxy quite a few times)
        auto bytes = string(header_size + data_length_size, (char)0xff);
        auto reader = Bytes::StringViewReader{bytes};

        // we don't support arbitrary length
        CHECK(!Length::read(reader));
    }

}

auto primitive_write(auto&& type, auto&& value, auto&& bytes) {
    auto writer = Bytes::StringWriter();
    FWD(type)(FWD(value)).write(writer);
    check_bytes(writer.string, FWD(bytes));
}
auto primitive_read(auto&& type, auto&& value, auto&& bytes) {
    auto reader = Bytes::StringViewReader{FWD(bytes)};
    CHECK(TRY(FWD(type).read(reader)) == FWD(value));
    check_bytes(reader.string, ""sv);
}
auto primitive_write_read(auto&& type, auto&& value, auto&& bytes) {
    primitive_write(FWD(type), FWD(value), FWD(bytes));
    primitive_read(FWD(type), FWD(value), FWD(bytes));
}
auto primitive_read_fail(auto&& type, auto&& bytes, auto&& remainder) {
    auto reader = Bytes::StringViewReader{FWD(bytes)};
    CHECK(!FWD(type).read(reader));
    check_bytes(reader.string, FWD(remainder));
}

TEST_CASE("primitives") {

    primitive_write_read(boolean, false, "\x01\x01\x00"sv);
    primitive_write_read(boolean, true, "\x01\x01\xff"sv);
    primitive_read(boolean, true, "\x01\x01\x01"sv);
    primitive_read_fail(boolean, "\x01\x02\x01\x42\x43"sv, "\x43"sv);
    primitive_write_read(integer, INT32_MIN, "\x02\x04\x80\x00\x00\x00"sv);
    primitive_write_read(integer, signed(0xdeadbeef), "\x02\x04\xDE\xAD\xBE\xEF"sv);
    primitive_write_read(integer, -(1 << 23) - 1, "\x02\x04\xff\x7f\xff\xff"sv);
    primitive_write_read(integer, -(1 << 23), "\x02\x03\x80\x00\x00"sv);
    primitive_write_read(integer, -(1 << 15) - 1, "\x02\x03\xff\x7f\xff"sv);
    primitive_write_read(integer, -(1 << 15), "\x02\x02\x80\x00"sv);
    primitive_write_read(integer, -129, "\x02\x02\xFF\x7F"sv);
    primitive_write_read(integer, -128, "\x02\x01\x80"sv);
    primitive_write_read(integer, -1, "\x02\x01\xFF"sv);
    primitive_write_read(integer, 0, "\x02\x01\x00"sv);
    primitive_write_read(integer, 1, "\x02\x01\x01"sv);
    primitive_write_read(integer, (1 << 7) - 1, "\x02\x01\x7F"sv);
    primitive_write_read(integer, (1 << 7), "\x02\x02\x00\x80"sv);
    primitive_write_read(integer, 256, "\x02\x02\x01\x00"sv);
    primitive_write_read(integer, (1 << 15) - 1, "\x02\x02\x7f\xff"sv);
    primitive_write_read(integer, (1 << 15), "\x02\x03\x00\x80\x00"sv);
    primitive_write_read(integer, (1 << 23) - 1, "\x02\x03\x7f\xff\xff"sv);
    primitive_write_read(integer, (1 << 23), "\x02\x04\x00\x80\x00\x00"sv);
    primitive_write_read(integer, INT32_MAX, "\x02\x04\x7f\xff\xff\xff"sv);
    primitive_write_read(octet_string, "hello"sv, "\x04\x05hello"sv);
    primitive_write_read(null, nullptr, "\x05\x00"sv);
    primitive_read_fail(null, "\x05\x01\x00\x42"sv, "\x42"sv);

}

TEST_CASE("sequence") {

    // auto bytes = "\x30\x06\x01\x01\xff\x02\x01\x42"sv;
    // auto reader = Reader(Bytes::StringViewReader{bytes});
    // auto sequence = TRY(reader.read_sequence());
    // auto element1 = TRY(sequence.read_boolean());
    // auto element2 = TRY(sequence.template read_integer<uint8_t>());

    // CHECK(element1 == true);
    // CHECK(element2 == 0x42);
    // check_bytes(sequence.bytes.string, ""sv);
    // check_bytes(reader.bytes.string, ""sv);

}

TEST_CASE("optional") {

    primitive_write(BER::optional(boolean), std::optional(false), "\x01\x01\x00"sv);
    primitive_write(BER::optional(boolean), std::optional<bool>(), ""sv);
    // primitive_write(optional(boolean), false, "\x01\x01\x00"sv);

}
