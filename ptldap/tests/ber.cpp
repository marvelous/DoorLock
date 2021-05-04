#define CATCH_CONFIG_FAST_COMPILE

#include "catch.hpp"
#include "tools.hpp"

#include "../ptldap.hpp"

TEST_CASE( "Parse BER::HeaderTag", "[BER::HeaderTag]" ) {
    SECTION("Simple Universal") {
        auto data = "\x02"s;
        auto ber_header_tag = BER::HeaderTag::parse(data);

        REQUIRE(ber_header_tag->get_size() == 1);
        REQUIRE(ber_header_tag->number == BER::HeaderTagNumber::Integer);
        REQUIRE(ber_header_tag->is_constructed == false);
        REQUIRE(ber_header_tag->asn1_class == BER::HeaderTagClass::Universal);
    }

    SECTION("Sequence Constructed Universal") {
        auto data = "\x30"s;
        auto ber_header_tag = BER::HeaderTag::parse(data);

        REQUIRE(ber_header_tag->get_size() == 1);
        REQUIRE(ber_header_tag->number == BER::HeaderTagNumber::Sequence);
        REQUIRE(ber_header_tag->is_constructed == true);
        REQUIRE(ber_header_tag->asn1_class == BER::HeaderTagClass::Universal);
    }

    SECTION("Extended Constructed Application") {
        auto data = "\x7f\xde\xad\x42"s;
        auto ber_header_tag = BER::HeaderTag::parse(data);

        auto size = ber_header_tag->get_size();

        for(uint8_t i = 0; i < size-1; i++) {
            INFO(i << ": " << (uint8_t)data.substr(1)[i] << " vs " << (uint8_t)ber_header_tag->buf_extra_tag_number()[i]);
            CHECK((uint8_t)data.substr(1)[i] == (uint8_t)ber_header_tag->buf_extra_tag_number()[i]);
        }

        REQUIRE(size == 4);
        REQUIRE(ber_header_tag->number == BER::HeaderTagNumber::ExtendedType);
        REQUIRE(ber_header_tag->is_constructed == true);
        REQUIRE(ber_header_tag->asn1_class == BER::HeaderTagClass::Application);
        REQUIRE(data.compare(1, size-1, ber_header_tag->buf_extra_tag_number()) == 0);
    }

    SECTION("From vector") {
        vector<char> v;
        v.push_back(0x02);
        auto ber_header_tag = BER::HeaderTag::parse(string_view(v.data(), v.size()));

        REQUIRE(ber_header_tag->get_size() == 1);
        REQUIRE(ber_header_tag->number == BER::HeaderTagNumber::Integer);
        REQUIRE(ber_header_tag->is_constructed == false);
        REQUIRE(ber_header_tag->asn1_class == BER::HeaderTagClass::Universal);
    }
}

TEST_CASE( "Parse BER::HeaderLength", "[BER::HeaderLength]" ) {
    SECTION("Short") {
        auto data = "\x7f"s;
        auto ber_header_length = BER::HeaderLength::parse(data);

        auto size = ber_header_length->get_size();
        REQUIRE(size == 1);
        REQUIRE(ber_header_length->is_long == false);
        REQUIRE(ber_header_length->length == 0x7f);
    }

    SECTION("Simple Long") {
        auto data = "\x81\x01"s;
        auto ber_header_length = BER::HeaderLength::parse(data);

        auto size = ber_header_length->get_size();
        REQUIRE(size == 2);
        REQUIRE(ber_header_length->is_long == true);
        REQUIRE(ber_header_length->length == 1);
        REQUIRE(ber_header_length->length_at(0) == 1);
    }

    SECTION("Smol Long") {
        // Create a string with the first byte (0x81) standing for: long-form, 1 byte for data length, data length of 255
        auto data = "\x81\xff";
        auto ber_header_length = BER::HeaderLength::parse(data);

        REQUIRE(ber_header_length->is_long == true);
        REQUIRE(ber_header_length->length == 1);
        REQUIRE(ber_header_length->length_at(0) == 255);
    }

    SECTION("Normal Long") {
        // Create a string with the first byte (0x84) standing for: long-form, 4 bytes for data length, data length of 2^32-2
        auto data = "\x84\xff\xff\xff\xfe";
        auto ber_header_length = BER::HeaderLength::parse(data);

        auto size = ber_header_length->get_size();
        REQUIRE(size == 5);
        REQUIRE(ber_header_length->is_long == true);
        REQUIRE(ber_header_length->length == 4);
        REQUIRE(ber_header_length->length_at(0) == 255);
        REQUIRE(ber_header_length->length_at(1) == 255);
        REQUIRE(ber_header_length->length_at(2) == 255);
        REQUIRE(ber_header_length->length_at(3) == 254);

        auto data_length_boring =
            (uint32_t)ber_header_length->length_at(0) << 24 |
            (uint32_t)ber_header_length->length_at(1) << 16 |
            (uint32_t)ber_header_length->length_at(2) << 8  |
            (uint32_t)ber_header_length->length_at(3);
        REQUIRE(data_length_boring == UINT32_MAX-1);

        // For length longer than typical integer max values, you can do funnier things to parse the remaining length
        // while parsing the rest of the data for example
        // Here, using an useless lambda to do the same thing as above
        auto data_length = ([ber_header_length](){
            auto size = ber_header_length->length;
            uint32_t length = 0;
            for(uint8_t i = 0; i < size; i++) {
                auto shift = ((size-i-1) * 8);
                length += ber_header_length->length_at(i) << shift;
            }
            return length;
        })();
        REQUIRE(data_length == UINT32_MAX-1);
    }

    SECTION("Long Long") {
        static const uint8_t header_size = 1;
        static const uint8_t data_length_size = 127;
        static const uint8_t null_char_size = 1;

        // Create a string with the first byte (0xff) standing for: long-form, 127 bytes for data length
        // And with 127 bytes of data length, all set to 255 (we are counting all particles in the galaxy quite a few times)
        auto data = string(header_size + data_length_size + null_char_size, (char)0xff);
        auto ber_header_length = BER::HeaderLength::parse(data);

        auto size = ber_header_length->get_size();
        REQUIRE(size == 128);
        REQUIRE(ber_header_length->is_long == true);
        REQUIRE(ber_header_length->length == 127);
        REQUIRE(ber_header_length->length_at(0) == 255);
        REQUIRE(ber_header_length->length_at(127) == 255);
    }
}

TEST_CASE( "Parse BER::Element", "[BER::Element]" ) {
    SECTION("Simple Integer") {
        auto test = [](shared_ptr<BER::Element> ber_element) {
            REQUIRE(ber_element->tag->number == BER::HeaderTagNumber::Integer);
            REQUIRE(ber_element->tag->is_constructed == false);
            REQUIRE(ber_element->tag->asn1_class == BER::HeaderTagClass::Universal);

            REQUIRE(ber_element->length->length == 4);
            REQUIRE(ber_element->length->is_long == false);

            // Do not parse as uint32_t as we don't know the endianness of the machine
            auto data_ptr = ber_element->get_data_ptr<uint8_t>();
            auto integer = ([data_ptr]() {
                uint32_t ret = 0;
                for(uint8_t i = 0; i < sizeof(uint32_t); i++) {
                    ret +=  data_ptr[i] << (8*(sizeof(uint32_t)-i-1));
                }
                return ret;
            })();
            REQUIRE(integer == 0xdeadbeef);
        };

        auto data = "\x02\x04\xDE\xAD\xBE\xEF"s;
        SECTION("Unchecked") {
            auto element_unchecked = BER::Element::parse_unchecked(data);
            REQUIRE(element_unchecked != nullptr);
            test(move(element_unchecked));
        }

        SECTION("Checked") {
            auto element_checked = BER::Element::parse(data);
            REQUIRE(element_checked != nullptr);
            test(move(element_checked));
        }
    }

    SECTION("Simple Integer") {
        auto data = "\x02\x04\xDE\xAD\xBE\xEF"s;
        auto ber_element = BER::Element::parse(data);
        REQUIRE(ber_element != nullptr);

        REQUIRE(ber_element->tag->number == BER::HeaderTagNumber::Integer);
        REQUIRE(ber_element->tag->is_constructed == false);
        REQUIRE(ber_element->tag->asn1_class == BER::HeaderTagClass::Universal);

        REQUIRE(ber_element->length->length == 4);
        REQUIRE(ber_element->length->is_long == false);

        // Do not parse as uint32_t as we don't know the endianness of the machine
        auto data_ptr = ber_element->get_data_ptr<uint8_t>();
        auto integer = ([data_ptr]() {
            uint32_t ret = 0;
            for(uint8_t i = 0; i < sizeof(uint32_t); i++) {
                ret +=  data_ptr[i] << (8*(sizeof(uint32_t)-i-1));
            }
            return ret;
        })();
        REQUIRE(integer == 0xdeadbeef);
    }

    SECTION("Simple string") {
        auto str = "hello"s;
        auto data = "\x04\x05"s + str;
        auto ber_element = BER::Element::parse(data);
        REQUIRE(ber_element != nullptr);

        REQUIRE(ber_element->tag->number == BER::HeaderTagNumber::OctetString);
        REQUIRE(ber_element->tag->is_constructed == false);
        REQUIRE(ber_element->tag->asn1_class == BER::HeaderTagClass::Universal);

        REQUIRE(ber_element->length->length == 5);
        REQUIRE(ber_element->length->is_long == false);

        typedef char SimpleString[5];
        REQUIRE(*ber_element->get_data_ptr<SimpleString>() == str);
    }
}

TEST_CASE( "Parse BER::UniversalElement", "[BER::UniversalElement]" ) {
    SECTION("Integer 8 bits") {
        auto data = "\x02\x01\x01"s;
        auto ber_element = BER::UniversalElement<BER::Integer>::parse(data);

        REQUIRE(ber_element->tag->number == BER::HeaderTagNumber::Integer);
        REQUIRE(ber_element->tag->is_constructed == false);
        REQUIRE(ber_element->tag->asn1_class == BER::HeaderTagClass::Universal);

        REQUIRE(ber_element->length->length == 1);
        REQUIRE(ber_element->length->is_long == false);

        REQUIRE(ber_element->get_value() == 1);
    }
    SECTION("Integer positive 16 bits") {
        auto data = "\x02\x03\x00\xDE\xAD"s;
        auto ber_element = BER::UniversalInteger::parse(data);

        REQUIRE(ber_element->tag->number == BER::HeaderTagNumber::Integer);
        REQUIRE(ber_element->tag->is_constructed == false);
        REQUIRE(ber_element->tag->asn1_class == BER::HeaderTagClass::Universal);

        REQUIRE(ber_element->length->length == 3);
        REQUIRE(ber_element->length->is_long == false);

        REQUIRE(ber_element->get_value() == 0xdead);
    }

    SECTION("Integer negative 16 bits") {
        auto data = "\x02\x02\xCF\xC7"s;
        auto ber_element = BER::UniversalInteger::parse(data);

        REQUIRE(ber_element->tag->number == BER::HeaderTagNumber::Integer);
        REQUIRE(ber_element->tag->is_constructed == false);
        REQUIRE(ber_element->tag->asn1_class == BER::HeaderTagClass::Universal);

        REQUIRE(ber_element->length->length == 2);
        REQUIRE(ber_element->length->is_long == false);

        REQUIRE(ber_element->get_value() == -12345);
    }

    SECTION("UniversalInteger") {
        auto data = "\x02\x01\x01"s;
        auto ber_element = BER::UniversalInteger::parse(data);

        REQUIRE(ber_element->tag->number == BER::HeaderTagNumber::Integer);
        REQUIRE(ber_element->tag->is_constructed == false);
        REQUIRE(ber_element->tag->asn1_class == BER::HeaderTagClass::Universal);

        REQUIRE(ber_element->length->length == 1);
        REQUIRE(ber_element->length->is_long == false);

        REQUIRE(ber_element->get_value() == 1);
    }

    SECTION("UniversalInteger 32 bits") {
        auto data = "\x02\x04\xDE\xAD\x13\x37"s;
        auto ber_element = BER::UniversalInteger::parse(data);

        REQUIRE(ber_element->tag->number == BER::HeaderTagNumber::Integer);
        REQUIRE(ber_element->tag->is_constructed == false);
        REQUIRE(ber_element->tag->asn1_class == BER::HeaderTagClass::Universal);

        REQUIRE(ber_element->length->length == 4);
        REQUIRE(ber_element->length->is_long == false);

        REQUIRE(ber_element->get_value() == 0xdead1337);
    }

    SECTION("UniversalString") {
        auto str = "hello"s;
        auto data = "\x04\x05"s + str;
        auto ber_element = BER::UniversalOctetString::parse(data);

        REQUIRE(ber_element->tag->number == BER::HeaderTagNumber::OctetString);
        REQUIRE(ber_element->tag->is_constructed == false);
        REQUIRE(ber_element->tag->asn1_class == BER::HeaderTagClass::Universal);

        REQUIRE(ber_element->length->length == 5);
        REQUIRE(ber_element->length->is_long == false);

        REQUIRE(ber_element->get_value() == str);
    }

    SECTION("Sequence") {
        auto data = "\x10\x06\x01\x01\xff\x02\x01\x42"s;
        auto ber_element = BER::UniversalElement<BER::Sequence>::parse(data);

        REQUIRE(ber_element->tag->number == BER::HeaderTagNumber::Sequence);
        REQUIRE(ber_element->tag->is_constructed == false);
        REQUIRE(ber_element->tag->asn1_class == BER::HeaderTagClass::Universal);

        REQUIRE(ber_element->length->length == 6);
        REQUIRE(ber_element->length->is_long == false);

        auto vec = ber_element->get_value();
        REQUIRE(vec.size() == 2);

        auto bool_ptr = vec[0];
        REQUIRE(bool_ptr->tag->number == BER::HeaderTagNumber::Boolean);
        auto bool_element = static_pointer_cast<BER::UniversalBoolean>(bool_ptr);
        REQUIRE(bool_element->get_value() == true);

        auto int_ptr = vec[1];
        REQUIRE(int_ptr->tag->number == BER::HeaderTagNumber::Integer);
        auto int_element = static_pointer_cast<BER::UniversalInteger>(int_ptr);
        REQUIRE(int_element->get_value() == 0x42);
    }
};