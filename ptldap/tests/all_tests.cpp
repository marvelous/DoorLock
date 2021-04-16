#define CATCH_CONFIG_FAST_COMPILE

#include "catch.hpp"
#include "tools.hpp"

#include "../ptldap.hpp"

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