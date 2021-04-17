#define CATCH_CONFIG_FAST_COMPILE

#include "catch.hpp"
#include "tools.hpp"

#include "../ptldap.hpp"

TEST_CASE( "Parse BER::Bool", "[BER::Bool]" ) {
    auto ber_bool_false = BER::Bool(false);
    auto ber_bool_true = BER::Bool(true);

    REQUIRE( ber_bool_false.value == false );
    REQUIRE( ber_bool_true.value == true );

    auto ber_bool_false_parsed = BER::Bool::parse("\x01\x01\x00"s);
    auto ber_bool_true_parsed = BER::Bool::parse("\x01\x01\x01"s);

    REQUIRE( ber_bool_false_parsed != nullptr );
    REQUIRE( ber_bool_true_parsed != nullptr );
    REQUIRE( ber_bool_false_parsed->value == false );
    REQUIRE( ber_bool_true_parsed->value == true );
}

TEST_CASE( "Parse BER::Integer", "[BER::Integer]" ) {
    auto ber_integer_u8 = BER::Integer<uint8_t>(0x42);
    auto ber_integer_u16 = BER::Integer<uint16_t>(0x42);
    auto ber_integer_u32 = BER::Integer<uint32_t>(0x42);

    REQUIRE( ber_integer_u8.value == 0x42 );
    REQUIRE( ber_integer_u16.value == 0x42 );
    REQUIRE( ber_integer_u32.value == 0x42 );

    auto ber_integer_u8_parsed = BER::Integer<uint8_t>::parse("\x02\x01\x42"s);
    auto ber_integer_u16_parsed = BER::Integer<uint16_t>::parse("\x02\x01\x42"s);
    auto ber_integer_u32_parsed = BER::Integer<uint32_t>::parse("\x02\x01\x42"s);

    REQUIRE( ber_integer_u8_parsed != nullptr );
    REQUIRE( ber_integer_u16_parsed != nullptr );
    REQUIRE( ber_integer_u32_parsed != nullptr );
    REQUIRE( ber_integer_u8_parsed->value == 0x42 );
    REQUIRE( ber_integer_u16_parsed->value == 0x42 );
    REQUIRE( ber_integer_u32_parsed->value == 0x42 );

    auto ber_integer_u32_parsed_as_u8 = BER::Integer<uint8_t>::parse("\x02\x02\x13\x37"s);
    REQUIRE( ber_integer_u32_parsed_as_u8 == nullptr );

    auto ber_integer_u8_parsed_as_u32 = BER::Integer<uint32_t>::parse("\x02\x01\x42"s);
    REQUIRE( ber_integer_u8_parsed_as_u32 != nullptr );
    REQUIRE( ber_integer_u8_parsed_as_u32->value == 0x42 );
}

TEST_CASE( "Parse BER::Enum", "[BER::Enum]" ) {
    auto ber_enum_type = BER::Enum<BER::Type>(BER::Type::Enum);

    REQUIRE( (uint8_t)ber_enum_type.value == (uint8_t)BER::Type::Enum );

    auto ber_enum_type_parsed = BER::Enum<BER::Type>::parse("\x0a\x01\x0a"s);

    REQUIRE( ber_enum_type_parsed != nullptr );
    REQUIRE( (uint8_t)ber_enum_type_parsed->value == (uint8_t)BER::Type::Enum );
}

TEST_CASE( "Parse BER::String", "[BER::String]" ) {
    auto expected_str = "I like trains"s;
    auto ber_string = BER::String(expected_str);

    REQUIRE( ber_string.value == expected_str );

    ostringstream oss;
    oss << "\x04" << (char)expected_str.size() << expected_str;

    REQUIRE( ber_string.str() == oss.str() );

    auto expected_str_non0 = {'H','E','N','L','O'};
    auto ber_string_non0 = BER::String(expected_str_non0);
    REQUIRE( ber_string_non0.value == string(expected_str_non0) );
}

TEST_CASE( "Generate a BindRequest", "[bindRequest]" ) {
    LDAP::MsgBuilder::reset_id();
    auto expected_str = "\x30\x21\x02\x01\x01\x60\x1c\x02\x01\x03\x04\x0a\x74\x65\x73\x74\x5f\x6c\x6f\x67\x69\x6e\x80\x0b\x74\x65\x73\x74\x5f\x70\x61\x73\x73\x77\x64"s;
    auto msg_str = LDAP::BindRequest("test_login", "test_passwd").str();

    REQUIRE( msg_str.size() == expected_str.size() );

    for (size_t i = 0 ; i < expected_str.size(); i++) {
        int expected_chr = (uint8_t)expected_str.c_str()[i];
        int msg_chr = (uint8_t)msg_str.c_str()[i];

        INFO("Error at index " << i);
        INFO("Got " << hex(msg_chr, 2) << ", expected " << hex(expected_chr, 2));
        CHECK(msg_chr == expected_chr);
    }

    REQUIRE( memcmp(expected_str.c_str(), msg_str.c_str(), expected_str.size()) == 0);
}

//TEST_CASE( "Parse a BindRequest", "[bindRequest]" ) {
//    LDAP::MsgBuilder::reset_id();
//    auto msg_str = "\x30\x21\x02\x01\x01\x60\x1c\x02\x01\x03\x04\x0a\x74\x65\x73\x74\x5f\x6c\x6f\x67\x69\x6e\x80\x0b\x74\x65\x73\x74\x5f\x70\x61\x73\x73\x77\x64"s;
//    auto msg_str = LDAP::BindRequest::parse("test_login", "test_passwd").str();
//
//    REQUIRE( msg_str.size() == expected_str.size() );
//
//    for (size_t i = 0 ; i < expected_str.size(); i++) {
//        int expected_chr = (uint8_t)expected_str.c_str()[i];
//        int msg_chr = (uint8_t)msg_str.c_str()[i];
//
//        INFO("Error at index " << i);
//        INFO("Got " << hex(msg_chr, 2) << ", expected " << hex(expected_chr, 2));
//        CHECK(msg_chr == expected_chr);
//    }
//
//    REQUIRE( memcmp(expected_str.c_str(), msg_str.c_str(), expected_str.size()) == 0);
//}

TEST_CASE( "Generate a SearchRequest", "[searchRequest]" ) {
    LDAP::MsgBuilder::reset_id();
    auto expected_str = "\x30\x57\x02\x01\x01\x63\x52\x04\x1c\x6f\x75\x3d\x4d\x61\x63\x68\x69\x6e\x65\x73\x2c\x64\x63\x3d\x73\x6b\x79\x6e\x65\x74\x2c\x64\x63\x3d\x6e\x65\x74\x0a\x01\x01\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\xa9\x1d\x82\x0f\x74\x6f\x70\x5f\x73\x65\x63\x72\x65\x74\x5f\x6e\x61\x6d\x65\x83\x0a\x54\x65\x72\x6d\x69\x6e\x61\x74\x6f\x72\x30\x04\x04\x02\x63\x6e"s;
    auto msg_str = LDAP::SearchRequest("ou=Machines,dc=skynet,dc=net",
                                       "top_secret_name",
                                       "Terminator",
                                       "cn").str();

    REQUIRE(msg_str.size() == expected_str.size() );

    for (size_t i = 0 ; i < expected_str.size(); i++) {
        int expected_chr = (uint8_t)expected_str.c_str()[i];
        int msg_chr = (uint8_t)msg_str.c_str()[i];

        INFO("Error at index " << i);
        INFO("Got " << hex(msg_chr, 2) << ", expected " << hex(expected_chr, 2));
        CHECK(msg_chr == expected_chr);
    }

    REQUIRE(memcmp(expected_str.c_str(), msg_str.c_str(), expected_str.size()) == 0);
}