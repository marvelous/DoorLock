// For more inspiration, see https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-ldap.c
// and http://luca.ntop.org/Teaching/Appunti/asn1.html
// and https://ldap.com/ldapv3-wire-protocol-reference-asn1-ber/

#include <string>
#include <type_traits>
#include <utility>
#include <vector>
#include <sstream>
#include <memory>
#include <iostream>
#include <cstring>
#include <optional>

namespace BER
{
    #include "string_view.hpp"

    using namespace nonstd::literals;
    using namespace nonstd;


    using namespace std;

    enum TypeTagNumber {
        Boolean = 0x01,
        Integer = 0x02,
        BitString = 0x03,
        OctetString = 0x04,
        Null = 0x05,
        ObjectIdentifier = 0x06,
        Sequence = 0x10,
        SequenceOf = 0x10,
        Set = 0x11,
        SetOf = 0x11,
        PrintableString = 0x13,
        T61String = 0x14,
        IA5String = 0x16,
        UTCTime = 0x17,
        ExtendedType = 0x1F,
    };

    enum TypeTagClass {
        Universal,
        Application,
        ContextSpecific,
        Private,
    };


    struct TypeTag {
        TypeTagClass tag_class;
        bool is_constructed;
        TypeTagNumber number;
    };

    template<typename Bytes>
    struct Reader {
        Bytes bytes;

        optional<uint8_t> read1() {
            auto string = bytes.read(1);
            if (string.empty()) return nullopt;
            return string[0];
        }

        bool empty() {
            return bytes.empty();
        }

        optional<TypeTag> read_type_tag() {
            auto c = read1();
            if (!c) return nullopt;
            auto tag_class = TypeTagClass((*c>>6) & 0b11);
            auto is_constructed = bool((*c>>5) & 0b1);
            auto number = TypeTagNumber((*c>>0) & 0b11111);
            return TypeTag{tag_class, is_constructed, number};
        }

    };
    template<typename Bytes>
    auto make_reader(Bytes read) {
        return Reader<Bytes>{move(read)};
    }

    auto make_string_reader(string_view string) {
        struct StringBytes {
            string_view string;
            string_view read(size_t size) {
                auto prefix = string.substr(0, size);
                string.remove_prefix(size);
                return prefix;
            }
            bool empty() {
                return string.empty();
            }
        } bytes{move(string)};
        return make_reader(move(bytes));
    }

}
