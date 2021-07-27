// ISO/IEC 8825-1:2015
// ASN.1 encoding rules: Specification of Basic Encoding Rules (BER),
// Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)
// https://www.iso.org/standard/68345.html
// https://standards.iso.org/ittf/PubliclyAvailableStandards/c068345_ISO_IEC_8825-1_2015.zip

// Wireshark implementation
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-ldap.c

// A Layman's Guide to a Subset of ASN.1, BER, and DER
// http://luca.ntop.org/Teaching/Appunti/asn1.html

// LDAPv3 Wire Protocol Reference: The ASN.1 Basic Encoding Rules
// https://ldap.com/ldapv3-wire-protocol-reference-asn1-ber/

#include "bytes.hpp"
#include <tuple>
#include <variant>
#include <experimental/array>

namespace BER {

    constexpr auto to_int(auto value) {
        using T = decltype(value);
        if constexpr (std::is_enum_v<T>) {
            return std::underlying_type_t<T>(value);
        } else {
            return value;
        }
    }

    enum class TagClass {
        Universal = 0b00,
        Application = 0b01,
        ContextSpecific = 0b10,
        Private = 0b11,
    };

    enum class Encoding {
        Primitive = 0b0,
        Constructed = 0b1,
    };

    enum class Universal {
        Boolean = 0x01,
        Integer = 0x02,
        BitString = 0x03,
        OctetString = 0x04,
        Null = 0x05,
        ObjectIdentifier = 0x06,
        Enumerated = 0x0a,
        Sequence = 0x10,
        SequenceOf = 0x10,
        Set = 0x11,
        SetOf = 0x11,
        PrintableString = 0x13,
        T61String = 0x14,
        IA5String = 0x16,
        UTCTime = 0x17,
    };
    const auto extended_type = to_int(Universal(0x1F));

    template<typename Bytes>
    struct Reader {

        Bytes bytes;

        explicit Reader(Bytes bytes): bytes(std::move(bytes)) {}

        auto read(auto const& type) {
            return type.read(*this);
        }

        // template<typename TagNumber>
        // std::optional<Identifier<TagNumber>> read_identifier() {
        //     auto byte = OPT_TRY(bytes.read());
        //     auto tag_class = TagClass((byte & 0b11000000) >> 6);
        //     auto encoding = Encoding((byte & 0b00100000) >> 5);
        //     auto tag_number = TagNumber((byte & 0b00011111) >> 0);

        //     if (tag_number == TagNumber(extended_type)) {
        //         auto tag_number_int = to_int(TagNumber(0));
        //         do {
        //             byte = OPT_TRY(bytes.read());
        //             tag_number_int = (tag_number_int << 7) | ((byte & 0b01111111) >> 0);
        //         } while ((byte & 0b10000000) >> 7);
        //         tag_number = TagNumber(tag_number_int);
        //     }

        //     return Identifier(tag_class, encoding, tag_number);
        // }

        // std::optional<Length> read_length() {
        //     auto byte = OPT_TRY(bytes.read());

        //     auto form = LengthForm((byte & 0b10000000) >> 7);
        //     if (form == LengthForm::Short) {
        //         return Length(byte);
        //     }

        //     auto count = (byte & 0b01111111) >> 0;
        //     if (count == LengthIndefinite) {
        //         return Length();
        //     }
        //     OPT_REQUIRE(count <= sizeof(size_t));

        //     auto length = size_t{0};
        //     for (auto i = 0u; i < count; ++i) {
        //         byte = OPT_TRY(bytes.read());
        //         length = (length << 8) | byte;
        //     }
        //     OPT_REQUIRE(length != SIZE_MAX);
        //     return Length(length);
        // }

        // template<typename T>
        // std::optional<T> read_integer() {
        //     auto identifier = OPT_TRY(read_identifier<TagNumber>());
        //     OPT_REQUIRE(identifier.tag_class == TagClass::Universal);
        //     OPT_REQUIRE(identifier.encoding == Encoding::Primitive);
        //     OPT_REQUIRE(identifier.tag_number == TagNumber::Integer);

        //     auto length = OPT_TRY(read_length()).length;
        //     OPT_REQUIRE(length > 0);

        //     auto first = int8_t(OPT_TRY(bytes.read()));
        //     if (std::is_unsigned_v<T> && first == 0) {
        //         OPT_REQUIRE(length - 1 <= sizeof(T));
        //     } else {
        //         OPT_REQUIRE(length <= sizeof(T));
        //     }

        //     auto value = T(first);
        //     for (auto shifts = length - 1; shifts; --shifts) {
        //         auto byte = OPT_TRY(bytes.read());
        //         value <<= 8;
        //         value |= byte;
        //     }
        //     return value;
        // }

        // template<typename T>
        // std::optional<typename T::Read> read() {
        //     return std::nullopt;
        // }

        // std::optional<nullptr_t> read_null() {
        //     auto identifier = OPT_TRY(read_identifier<TagNumber>());
        //     OPT_REQUIRE(identifier.tag_class == TagClass::Universal);
        //     OPT_REQUIRE(identifier.encoding == Encoding::Primitive);
        //     OPT_REQUIRE(identifier.tag_number == TagNumber::Null);

        //     auto length = OPT_TRY(read_length());
        //     OPT_REQUIRE(length.length == 0);

        //     return nullptr;
        // }

        // std::optional<bool> read_boolean() {
        //     auto identifier = OPT_TRY(read_identifier<TagNumber>());
        //     OPT_REQUIRE(identifier.tag_class == TagClass::Universal);
        //     OPT_REQUIRE(identifier.encoding == Encoding::Primitive);
        //     OPT_REQUIRE(identifier.tag_number == TagNumber::Boolean);

        //     auto length = OPT_TRY(read_length());
        //     OPT_REQUIRE(length.length == 1);

        //     return OPT_TRY(bytes.read());
        // }

        // std::optional<nonstd::string_view> read_octet_string() {
        //     auto identifier = OPT_TRY(read_identifier<TagNumber>());
        //     OPT_REQUIRE(identifier.tag_class == TagClass::Universal);
        //     OPT_REQUIRE(identifier.tag_number == TagNumber::OctetString);

        //     return read_octet_string(identifier);
        // }

        // template<typename TagNumber>
        // std::optional<nonstd::string_view> read_octet_string(Identifier<TagNumber> const& identifier) {
        //     OPT_REQUIRE(identifier.encoding == Encoding::Primitive);

        //     auto length = OPT_TRY(read_length());
        //     OPT_REQUIRE(!length.is_indefinite());

        //     return bytes.read(length.length);
        // }

        // std::optional<Reader<Bytes>> read_sequence() {
        //     auto identifier = OPT_TRY(read_identifier<TagNumber>());
        //     OPT_REQUIRE(identifier.tag_class == TagClass::Universal);
        //     OPT_REQUIRE(identifier.tag_number == TagNumber::Sequence);

        //     return read_sequence(identifier);
        // }

        // template<typename TagNumber>
        // std::optional<Reader<Bytes>> read_sequence(Identifier<TagNumber> const& identifier) {
        //     OPT_REQUIRE(identifier.encoding == Encoding::Constructed);

        //     auto length = OPT_TRY(read_length());
        //     OPT_REQUIRE(!length.is_indefinite());

        //     return Reader<Bytes>{OPT_TRY(bytes.reader(length.length))};
        // }

    };

    struct BytesCounter {

        size_t count = 0;

        void write(uint8_t byte) {
            ++count;
        }

        void write(std::string_view bytes) {
            count += bytes.size();
        }

    };

    template<typename Bytes>
    struct Writer {

        Bytes bytes;

        explicit Writer(Bytes bytes): bytes(std::move(bytes)) {}

        void write(auto const& value) {
            value.write(*this);
        }

    };

    template<typename T>
    uint8_t count_bits(T value) {
        if (value < 0) value = ~value;

        auto bits = uint8_t{0};
        while (value) {
            ++bits;
            value >>= 1;
        }
        return bits;
    }

    enum class LengthForm {
        Short = 0b0,
        Long = 0b1,
    };

    constexpr uint8_t LengthIndefinite = 0b0000000;

    struct Length {

        size_t length;

        explicit Length(size_t length): length(length) {}
        explicit Length(): length(SIZE_MAX) {}

        bool is_indefinite() const {
            return length == SIZE_MAX;
        }

        template<typename Writer>
        void write(Writer& writer) const {
            auto write_length = [&](LengthForm length_form, uint8_t length) {
                writer.bytes.write((to_int(length_form) << 7) | (length << 0));
            };

            if (is_indefinite()) {
                write_length(LengthForm::Long, LengthIndefinite);
                return;
            }

            auto count = length;
            if (count <= 0b01111111) {
                write_length(LengthForm::Short, count);
                return;
            }

            auto shifts = (count_bits(count) - 1) / 8;
            auto length_length = shifts + 1;
            write_length(LengthForm::Long, length_length);
            for (auto shift = shifts * 8; shift; shift -= 8) {
                writer.bytes.write((count >> shift) & 0b11111111);
            }
            writer.bytes.write(count & 0b11111111);
        }

    };

    // template<typename ... Elements>
    // struct Sequence {
    //     template<typename Element>
    //     using Read1 = typename Element::Read;
    //     using Read = std::tuple<Read1<Elements>...>;

    //     std::tuple<Elements...> value;

    //     template<typename ... Args>
    //     Sequence(Args&&... args): value(std::forward<Args>(args)...) {}

    //     template<typename Writer>
    //     void write(Writer& writer) const {
    //         std::apply([&](auto&&... args){ (writer.write(args), ...); }, value);
    //     }

    // };

    // template<typename Element, size_t size>
    // struct SequenceOf {
    //     struct Read {
    //         std::optional<typename Element::Read> read() {
    //             return std::nullopt;
    //         }
    //     };

    //     std::array<Element, size> value;

    //     template<typename ... Args>
    //     SequenceOf(Args&&... args): value(std::forward<Args&&>(args)...) {}
    // };

    // template<typename TagNumber, typename Type>
    // struct Tagged {

    //     TagClass tag_class;
    //     TagNumber tag_number;
    //     Type type;

    //     Tagged(auto&& tag_class, auto&& tag_number, auto&& type):
    //         tag_class(std::forward<decltype(tag_class)>(tag_class)),
    //         tag_number(std::forward<decltype(tag_number)>(tag_number)),
    //         type(std::forward<decltype(type)>(type)) {}

    // };
    // constexpr auto tag(auto&& tag_class, auto&& tag_number, auto&& type) {
    //     return Tagged(std::forward<decltype(tag_class)>(tag_class),
    //         std::forward<decltype(tag_number)>(tag_number),
    //         std::forward<decltype(type)>(type));
    // }
    // constexpr auto tag(auto&& tag_number, auto&& type) {
    //     return Tagged(TagClass::ContextSpecific,
    //         std::forward<decltype(tag_number)>(tag_number),
    //         std::forward<decltype(type)>(type));
    // }

    template<typename Type, typename Value>
    struct Writable {

        Type type;
        Value value;

        explicit constexpr Writable(Type type, Value value):
            type(std::forward<decltype(type)>(type)),
            value(std::forward<decltype(value)>(value)) {}

        void write(auto& output) const {
            auto tag_class = to_int(type.tag_class);
            auto encoding = to_int(type.encoding);
            auto tag_number = to_int(type.tag_number);

            auto write0 = [&](auto tag_number) {
                output.bytes.write((tag_class << 6) | (encoding << 5) | (tag_number << 0));
            };
            if (tag_number < extended_type) {
                write0(tag_number);
            } else {
                write0(extended_type);
                auto shifts = (count_bits(tag_number) - 1) / 7;
                for (auto shift = shifts * 7; shift; shift -= 7) {
                    output.bytes.write(0b10000000 | (tag_number >> shift) & 0b01111111);
                }
                output.bytes.write(0b00000000 | (tag_number & 0b01111111));
            }

            type.writer.write(output, value);
        }

    };

    template<Encoding e, TagClass c, typename T, typename W>
    struct Type {

        static constexpr auto encoding = e;
        static constexpr auto tag_class = c;
        using TagNumber = T;
        using Writer = W;

        TagNumber tag_number;
        Writer writer;

        explicit constexpr Type(TagNumber tag_number, Writer writer):
            tag_number(std::forward<decltype(tag_number)>(tag_number)),
            writer(std::forward<decltype(writer)>(writer)) {}

        constexpr auto context_specific(auto tag_number) const {
            using Result = Type<encoding, TagClass::ContextSpecific, decltype(tag_number), Writer>;
            return Result(std::forward<decltype(tag_number)>(tag_number), writer);
        }

        constexpr auto application(auto tag_number) const {
            using Result = Type<encoding, TagClass::Application, decltype(tag_number), Writer>;
            return Result(std::forward<decltype(tag_number)>(tag_number), writer);
        }

        constexpr auto optional() const {
            // TODO
            return *this;
        }

        constexpr auto operator()(auto&&... args) const {
            return BER::Writable(*this, writer(std::forward<decltype(args)>(args)...));
        }

        // null
        void write(auto& writer) const {
            writer.write((*this)());
        }

        auto read(auto& reader) const {

            return std::optional{0}; // TODO
        }

    };
    template<Encoding encoding>
    constexpr auto universal_type(Universal tag_number, auto writer) {
        return Type<encoding, TagClass::Universal, Universal, decltype(writer)>(tag_number, writer);
    }

    struct Null {

        auto operator()() const {
            return nullptr;
        }

        void write(auto& writer, auto const& value) const {
            writer.write(Length(0));
        }

    };
    constexpr auto null = universal_type<Encoding::Primitive>(Universal::Null, Null());

    struct Integer {

        auto operator()(auto value) const {
            return std::move(value);
        }

        void write(auto& writer, auto const& value) const {
            auto shifts = count_bits(value) / 8;
            writer.write(Length(shifts + 1));
            for (auto shift = shifts * 8; shift; shift -= 8) {
                writer.bytes.write((value >> shift) & 0b11111111);
            }
            writer.bytes.write(value & 0b11111111);
        }

    };
    constexpr auto integer = universal_type<Encoding::Primitive>(Universal::Integer, Integer());

    struct Boolean {

        bool operator()(auto value) const {
            return value;
        }

        void write(auto& writer, bool value) const {
            writer.write(Length(1));
            writer.bytes.write(value ? 0xff : 0x00);
        }

    };
    constexpr auto boolean = universal_type<Encoding::Primitive>(Universal::Boolean, Boolean());

    struct OctetString {

        auto operator()(auto value) const {
            return value;
        }

        void write(auto& writer, auto const& value) const {
            writer.write(Length(value.size()));
            writer.bytes.write(value);
        }

    };
    constexpr auto octet_string = universal_type<Encoding::Primitive>(Universal::OctetString, OctetString());

    template<typename ... Types>
    struct Sequence {

        std::tuple<Types...> types;
        explicit constexpr Sequence(auto&&... types):
            types(std::forward<decltype(types)>(types)...) {}

        template<typename X, size_t ...i>
        auto for_each() {}
        auto operator()(auto&&... args) const {
            // template<size_t ...i>
            std::index_sequence_for<decltype(args)...>{};
            return std::tuple(std::forward<decltype(args)>(args)...);
        }

        void write(auto& writer, auto const& value) const {
            auto counter = Writer<BytesCounter>{BytesCounter()};
            write_elements(counter, value);
            writer.write(Length(counter.bytes.count));
            write_elements(writer, value);
        }

        void write_elements(auto& writer, auto const& elements) const {
            // TODO
            // std::apply([&](auto&&... args){ (writer.write(args), ...); }, elements);
        }

    };
    constexpr auto sequence(auto&&... args) {
        return universal_type<Encoding::Constructed>(Universal::Sequence,
            Sequence<std::decay_t<decltype(args)>...>(std::forward<decltype(args)>(args)...));
    }

    template<typename Type>
    struct SequenceOf {

        Type type;
        explicit constexpr SequenceOf(auto&& type):
            type(std::forward<decltype(type)>(type)) {}

        auto operator()(auto&&... args) const {
            return std::experimental::make_array(type(std::forward<decltype(args)>(args))...);
        }

        void write(auto& writer, auto const& value) const {
            auto counter = Writer<BytesCounter>{BytesCounter()};
            write_elements(counter, value);
            writer.write(Length(counter.bytes.count));
            write_elements(writer, value);
        }

        void write_elements(auto& writer, auto const& elements) const {
            for (auto const& element : elements) {
                writer.write(element);
            }
        }

    };
    constexpr auto sequence_of(auto&& type) {
        return universal_type<Encoding::Constructed>(Universal::SequenceOf,
            SequenceOf<std::decay_t<decltype(type)>>(std::forward<decltype(type)>(type)));
    }

    // template<typename ... Choices>
    // struct Choice {

    //     struct Read {

    //         TagNumber tag_number;

    //         template<typename T>
    //         std::optional<typename T::Read> read() {
    //             return std::nullopt;
    //         }

    //     };

    //     std::variant<Choices...> value;

    //     template<typename ... Args>
    //     Choice(Args&&... args): value(std::forward<Args>(args)...) {}

    // };

}
