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

    template<typename N>
    struct Identifier {

        using TagNumber = N;
        static constexpr auto extended_type = 0x1F;

        Encoding encoding;
        TagClass tag_class;
        TagNumber tag_number;

        explicit constexpr Identifier(Encoding encoding, TagClass tag_class, TagNumber tag_number):
            encoding(FWD(encoding)),
            tag_class(FWD(tag_class)),
            tag_number(FWD(tag_number)) {}

        void write(auto& writer) const {
            auto tag_class = to_int(this->tag_class);
            auto encoding = to_int(this->encoding);
            auto tag_number = to_int(this->tag_number);

            auto write0 = [&](auto tag_number) {
                writer.write((tag_class << 6) | (encoding << 5) | (tag_number << 0));
            };
            if (tag_number < extended_type) {
                write0(tag_number);
            } else {
                write0(extended_type);
                auto shifts = (count_bits(tag_number) - 1) / 7;
                for (auto shift = shifts * 7; shift; shift -= 7) {
                    writer.write(0b10000000 | (tag_number >> shift) & 0b01111111);
                }
                writer.write(0b00000000 | (tag_number & 0b01111111));
            }
        }

        static std::optional<Identifier> read(auto& reader) {
            auto byte = OPT_TRY(reader.read());
            auto tag_class = TagClass((byte & 0b11000000) >> 6);
            auto encoding = Encoding((byte & 0b00100000) >> 5);
            auto tag_number = TagNumber((byte & 0b00011111) >> 0);

            if (tag_number == TagNumber(extended_type)) {
                auto tag_number_int = to_int(TagNumber(0));
                do {
                    byte = OPT_TRY(reader.read());
                    tag_number_int = (tag_number_int << 7) | ((byte & 0b01111111) >> 0);
                } while ((byte & 0b10000000) >> 7);
                tag_number = TagNumber(std::move(tag_number_int));
            }

            return Identifier(encoding, tag_class, std::move(tag_number));
        }

        bool operator==(Identifier const& that) const {
            return this->encoding == that.encoding && this->tag_class == that.tag_class && this->tag_number == that.tag_number;
        }

    };

    struct Length {

        enum class Form {
            Short = 0b0,
            Long = 0b1,
        };

        static constexpr uint8_t Indefinite = 0b0000000;

        std::optional<size_t> length;
        explicit Length(std::optional<size_t>&& length): length(FWD(length)) {}

        bool is_indefinite() const {
            return !length.has_value();
        }

        void write(auto& bytes) const {
            auto write_length = [&](Form form, uint8_t length) {
                bytes.write((to_int(form) << 7) | (length << 0));
            };

            if (is_indefinite()) {
                write_length(Form::Long, Indefinite);
                return;
            }

            auto count = *length;
            if (count <= 0b01111111) {
                write_length(Form::Short, count);
                return;
            }

            auto shifts = (count_bits(count) - 1) / 8;
            auto length_length = shifts + 1;
            write_length(Form::Long, length_length);
            for (auto shift = shifts * 8; shift; shift -= 8) {
                bytes.write((count >> shift) & 0b11111111);
            }
            bytes.write(count & 0b11111111);
        }

        static std::optional<Length> read(auto& reader) {
            auto byte = OPT_TRY(reader.read());

            auto form = Form((byte & 0b10000000) >> 7);
            if (form == Form::Short) {
                return Length(byte);
            }

            auto count = (byte & 0b01111111) >> 0;
            if (count == Indefinite) {
                return Length(std::nullopt);
            }
            OPT_REQUIRE(count <= sizeof(size_t));

            auto length = size_t{0};
            for (auto i = 0u; i < count; ++i) {
                byte = OPT_TRY(reader.read());
                length = (length << 8) | byte;
            }
            OPT_REQUIRE(length != SIZE_MAX);
            return Length(length);
        }

    };

    template<typename Type, typename Value>
    struct Writable {

        Type type;
        Value value;

        explicit constexpr Writable(Type type, Value value):
            type(FWD(type)),
            value(FWD(value)) {}

        void write(auto& writer) const {
            type.write(writer, value);
        }

    };

    template<typename I, typename S>
    struct Type {

        using Identifier = I;
        using Serde = S;

        Identifier identifier;
        Serde serde;

        explicit constexpr Type(Identifier identifier, Serde serde):
            identifier(FWD(identifier)),
            serde(FWD(serde)) {}

        constexpr auto tagged(TagClass tag_class, auto tag_number) const {
            return BER::Type(BER::Identifier(identifier.encoding, tag_class, tag_number), serde);
        }

        constexpr auto context_specific(auto tag_number) const {
            return tagged(TagClass::ContextSpecific, tag_number);
        }

        constexpr auto application(auto tag_number) const {
            return tagged(TagClass::Application, tag_number);
        }

        template<typename Value>
        constexpr auto operator()(const BER::Writable<Type, Value>& writable) const {
            return writable;
        }
        constexpr auto operator()(auto&&... args) const {
            return BER::Writable(*this, serde(FWD(args)...));
        }

        void write(auto& writer, auto& value) const {
            identifier.write(writer);

            auto counter = Bytes::CounterWriter();
            serde.write(counter, value);
            Length(counter.count).write(writer);

            serde.write(writer, value);
        }

        auto read(auto& reader) const -> decltype(serde.read(reader)) {
            auto identifier = OPT_TRY(Identifier::read(reader));
            OPT_REQUIRE(identifier == this->identifier);

            auto length = OPT_TRY(Length::read(reader));
            OPT_REQUIRE(!length.is_indefinite());

            auto bytes = OPT_TRY(reader.reader(*length.length));
            auto value = serde.read(bytes);
            OPT_REQUIRE(bytes.empty());
            return value;
        }

    };
    constexpr auto type(Encoding encoding, auto&& tag_number, auto&& serde) {
        return Type(Identifier(encoding, TagClass::Universal, FWD(tag_number)), FWD(serde));
    }

    struct Boolean {

        auto operator()(bool value) const {
            return value;
        }

        void write(auto& writer, bool value) const {
            writer.write(value ? 0xff : 0x00);
        }

        std::optional<bool> read(auto& reader) const {
            return OPT_TRY(reader.read()) != 0x00;
        }

    };
    constexpr auto boolean = type(Encoding::Primitive, 0x01, Boolean());

    template<typename Integral = int> // TODO
    struct Integer {

        Integral operator()(auto&& value) const {
            return FWD(value);
        }

        void write(auto& writer, auto const& value) const {
            auto shifts = count_bits(value) / 8;
            for (auto shift = shifts * 8; shift; shift -= 8) {
                writer.write((value >> shift) & 0b11111111);
            }
            writer.write(value & 0b11111111);
        }

        std::optional<Integral> read(auto& reader) const {
            auto length = reader.size();
            auto first = int8_t(OPT_TRY(reader.read()));

            if (std::is_unsigned_v<Integral> && first == 0) {
                OPT_REQUIRE(length - 1 <= sizeof(Integral));
            } else {
                OPT_REQUIRE(length <= sizeof(Integral));
            }

            auto value = Integral(first);
            for (auto shifts = length - 1; shifts; --shifts) {
                auto byte = OPT_TRY(reader.read());
                value <<= 8;
                value |= byte;
            }
            return value;
        }

    };
    constexpr auto integer = type(Encoding::Primitive, 2, Integer());

    struct OctetString {

        auto operator()(auto&& value) const {
            return FWD(value);
        }

        void write(auto& writer, auto const& value) const {
            writer.write(value);
        }

        std::optional<std::string_view> read(auto& reader) const {
            return OPT_TRY(reader.read(reader.size()));
        }

    };
    constexpr auto octet_string = type(Encoding::Primitive, 4, OctetString());

    struct Null {

        constexpr auto operator()(nullptr_t value = nullptr) const {
            return value;
        }

        void write(auto& writer, auto const& value) const {
            // nothing to write
        }

        std::optional<std::nullptr_t> read(auto& reader) const {
            return nullptr;
        }

    };
    constexpr auto null = type(Encoding::Primitive, 5, Null());

    template<typename ... Types>
    struct Sequence {

        std::tuple<Types...> types;
        explicit constexpr Sequence(auto&&... types):
            types(FWD(types)...) {}

        auto operator()(auto&&... args) const {
            static_assert(sizeof...(Types) == sizeof...(args));
            return std::tuple(FWD(args)...);
        }

        void write(auto& writer, auto const& elements) const {
            auto indices = std::make_index_sequence<sizeof...(Types)>{};
            write_elements(writer, elements, indices);
        }
        template<size_t ... indices>
        void write_elements(auto& writer, auto const& elements, std::index_sequence<indices...>) const {
            (std::get<indices>(types)(std::get<indices>(elements)).write(writer), ...);
        }

        auto read(auto& reader) const {
            return read_elements<0>(reader);
        }
        template<size_t i>
        auto read_elements(auto& reader, auto&&... values) const {
            if constexpr (i < sizeof...(Types)) {
                auto value = std::get<i>(types).read(reader);
                if (!value) {
                    return decltype(read_elements<i + 1>(reader, FWD(values)..., FWD(*value))){};
                }
                return read_elements<i + 1>(reader, FWD(values)..., FWD(*value));
            } else {
                return std::optional(std::tuple(FWD(values)...));
            }
        }

    };
    constexpr auto sequence(auto&&... elements) {
        return type(Encoding::Constructed, 0x10, Sequence<std::decay_t<decltype(elements)>...>(FWD(elements)...));
    }

    template<typename Type>
    struct SequenceOf {

        Type type;
        explicit constexpr SequenceOf(auto&& type):
            type(FWD(type)) {}

        auto operator()(auto&&... args) const {
            return std::experimental::make_array(FWD(args)...);
        }

        void write(auto& writer, auto const& elements) const {
            for (auto const& element : elements) {
                type(element).write(writer);
            }
        }

        auto read(auto& reader) const -> decltype(reader.reader(0)) {
            auto size = reader.size();
            return OPT_TRY(reader.reader(size));
        }

    };
    constexpr auto sequence_of(auto&& type) {
        return BER::type(Encoding::Constructed, 0x10, SequenceOf<std::decay_t<decltype(type)>>(FWD(type)));
    }

    template<typename Type>
    struct Optional {

        Type type;
        explicit constexpr Optional(auto&& type):
            type(FWD(type)) {}

        constexpr auto operator()(auto&& value) const {
            return BER::Writable(*this, FWD(value));
        }

        void write(auto& writer, std::nullopt_t) const {
            // write nothing
        }
        void write(auto& writer, auto&& value) const {
            type(FWD(value)).write(writer);
        }
        template<typename Value>
        void write(auto& writer, std::optional<Value> const& value) const {
            if (value) {
                type(*value).write(writer);
            }
        }

        auto read(auto& reader) const {
            auto state = reader;
            auto result = type.read(reader);
            if (!result) {
                // put back consumed bytes
                reader = FWD(state);
            }
            return std::optional<decltype(result)>(FWD(result));
        }

    };
    constexpr auto optional(auto&& type) {
        return Optional<std::decay_t<decltype(type)>>(FWD(type));
    }

    template<typename TagNumber, typename ... Types>
    struct Choice {

        std::tuple<Types...> types;
        explicit constexpr Choice(auto&&... types): types(FWD(types)...) {}

        template<TagNumber tag_number>
        constexpr auto make(auto&&... values) const {
            if constexpr (tag_number == std::get<0>(types).identifier.tag_number) {
                
            }
        }
        constexpr auto operator()(auto&& value) const {
            return FWD(value);
        }

        template<typename ... Values>
        struct Read {
            using Value = typename std::variant<Values...>;
            Identifier<TagNumber> identifier;
            Value value;
        };
        template<size_t i, typename ... Values>
        auto read_choices(auto& reader, auto&& identifier) const {
            if constexpr (i < sizeof...(Types)) {
                auto& type = std::get<i>(types);
                using Value = std::decay_t<decltype(*type.read(reader))>;
                using Result = decltype(read_choices<i + 1, Values..., Value>(reader, identifier));
                using Pair = typename Result::value_type;
                using Variant = typename Pair::second_type;
                if (identifier == type.identifier) {
                    auto&& result = type.serde.read(reader);
                    if (!result) {
                        return Result(std::nullopt);
                    }
                    return Result({FWD(identifier), Variant(std::in_place_index_t<i>(), *FWD(result))});
                } else {
                    return read_choices<i + 1, Values..., Value>(reader, FWD(identifier));
                }
            } else {
                return std::optional<std::pair<Identifier<TagNumber>, std::variant<Values...>>>(std::nullopt);
            }
        }
        auto read(auto& reader) const -> decltype(read_choices<0>(reader, *Identifier<TagNumber>::read(reader))) {
            auto&& identifier = OPT_TRY(Identifier<TagNumber>::read(reader));

            auto length = OPT_TRY(Length::read(reader));
            OPT_REQUIRE(!length.is_indefinite());

            auto bytes = OPT_TRY(reader.reader(*length.length));
            return read_choices<0>(bytes, FWD(identifier));
        }

    };
    // TODO: compute common TagNumber from types instead of typename
    template<typename TagNumber = int>
    constexpr auto choice(auto&&... types) {
        return Choice<TagNumber, std::decay_t<decltype(types)>...>(FWD(types)...);
    }

}
