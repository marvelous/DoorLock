// Lightweight Directory Access Protocol (LDAP): The Protocol
// https://datatracker.ietf.org/doc/html/rfc4511

// LDAPv3 Wire Protocol Reference
// https://ldap.com/ldapv3-wire-protocol-reference/

#include "ber.hpp"

namespace LDAP {

    enum class TagNumber {
        Controls = 0,
        BindRequest = 0,
        SearchRequest = 3,
        DelRequest = 10,
    };

    struct DelRequest {
        std::string_view dn;
    };

    template<typename Authentication>
    struct BindRequest {
        uint8_t version;
        std::string_view name;
        Authentication authentication;
    };

    namespace Authentication {

        enum class TagNumber {
            Simple = 0,
            Sasl = 3,
        };

        struct Simple {
            std::string_view password;
        };

    }

    namespace Filter {

        template<typename ... Filters>
        auto and_(Filters ... filters) {
            return 0;
        }

        auto equalityMatch(std::string_view attributeDesc, std::string_view assertionValue) {
            return 0;
        }

    }

    enum class Scope {
        BaseObject = 0x0,
        SingleLevel = 0x1,
        WholeSubtree = 0x2,
    };

    enum class DerefAliases {
        NeverDerefAliases = 0x0,
        DerefInSearching = 0x1,
        DerefFindingBaseObj = 0x2,
        DerefAlways = 0x3,
    };

    template<typename Filter>
    struct SearchRequest {
        std::string_view base_object;
        Scope scope;
        DerefAliases deref_aliases;
        size_t size_limit;
        size_t time_limit;
        bool types_only;
        Filter filter;
        std::initializer_list<std::string_view> attributes;
    };

    struct Control {
        std::string_view control_type;
        bool criticality;
        std::optional<std::string_view> control_value;
    };

    template<typename BERReader>
    struct BindRequestReader {

        uint8_t version;
        std::string_view name;
        BER::Identifier<Authentication::TagNumber> identifier;
        BERReader ber;

        std::optional<std::string_view> read_simple() {
            OPT_REQUIRE(identifier.tag_number == Authentication::TagNumber::Simple);
            return OPT_TRY(ber.read_octet_string(identifier));
        }

    };

    template<typename BERReader>
    struct ControlsReader {

        BERReader ber;

        std::optional<Control> read_control() {
            auto sequence = OPT_TRY(ber.read_sequence());
            auto control_type = OPT_TRY(sequence.read_octet_string());
            auto criticality = OPT_TRY(sequence.read_boolean());

            if (sequence.bytes.empty()) {
                return Control{control_type, criticality, std::nullopt};
            }
            auto control_value = OPT_TRY(sequence.read_octet_string());

            OPT_REQUIRE(sequence.bytes.empty());
            return Control{control_type, criticality, control_value};
        }

    };

    template<typename BERReader>
    struct MessageReader {

        int32_t message_id;
        BER::Identifier<TagNumber> identifier;
        BERReader ber;

        std::optional<BindRequestReader<BERReader>> read_bind_request() {
            OPT_REQUIRE(identifier.tag_number == TagNumber::BindRequest);

            auto sequence = OPT_TRY(ber.read_sequence(identifier));
            auto version = OPT_TRY(sequence.template read_integer<uint8_t>());
            auto name = OPT_TRY(sequence.read_octet_string());
            auto auth_choice = OPT_TRY(sequence.template read_identifier<Authentication::TagNumber>());
            OPT_REQUIRE(auth_choice.tag_class == BER::TagClass::ContextSpecific);
            return BindRequestReader<BERReader>{version, name, auth_choice, std::move(sequence)};
        }

        std::optional<DelRequest> read_del_request() {
            OPT_REQUIRE(identifier.tag_number == TagNumber::DelRequest);
            auto dn = OPT_TRY(ber.read_octet_string(identifier));
            return DelRequest{dn};
        }

        std::optional<ControlsReader<BERReader>> read_controls() {
            auto identifier = OPT_TRY(ber.template read_identifier<TagNumber>());
            OPT_REQUIRE(identifier.tag_class == BER::TagClass::ContextSpecific);
            OPT_REQUIRE(identifier.tag_number == TagNumber::Controls);

            auto sequence = OPT_TRY(ber.read_sequence(identifier));
            return ControlsReader<BERReader>{std::move(sequence)};
        }

    };

    template<typename BERReader>
    struct Reader {

        BERReader ber;

        Reader(BERReader ber): ber(std::move(ber)) {}

        std::optional<MessageReader<BERReader>> read_message() {
            auto sequence = OPT_TRY(ber.read_sequence());

            auto message_id = OPT_TRY(sequence.template read_integer<int32_t>());
            OPT_REQUIRE(message_id >= 0);

            auto identifier = OPT_TRY(sequence.template read_identifier<TagNumber>());
            OPT_REQUIRE(identifier.tag_class == BER::TagClass::Application);

            return MessageReader<BERReader>{message_id, identifier, std::move(sequence)};
        }

    };

    template<typename BERWriter>
    struct Writer {

        BERWriter ber;

        Writer(BERWriter ber): ber(std::move(ber)) {}

        template<typename ProtocolOp>
        void write_message(int32_t message_id, ProtocolOp const& protocol_op) {
            ber.write_sequence(message_id, protocol_op);
        }

        template<typename ProtocolOp, typename ... Controls>
        void write_message(int32_t message_id, ProtocolOp const& protocol_op, Controls const& ... controls) {
            ber.write_sequence(message_id, protocol_op, std::initializer_list{controls...});
        }

    };

}

namespace BER {

    template<typename Writer, typename Authentication>
    void write_data(Writer& writer, LDAP::BindRequest<Authentication> const& request) {
        writer.write_sequence(BER::Identifier(TagClass::Application, Encoding::Constructed, LDAP::TagNumber::BindRequest), request.version, request.name, request.authentication);
    }

    template<typename Writer>
    void write_data(Writer& writer, LDAP::Authentication::Simple const& authentication) {
        writer.write_octet_string(BER::Identifier(TagClass::ContextSpecific, Encoding::Primitive, LDAP::Authentication::TagNumber::Simple), authentication.password);
    }

    template<typename Writer>
    void write_data(Writer& writer, LDAP::DelRequest const& request) {
        writer.write_octet_string(BER::Identifier(TagClass::Application, Encoding::Primitive, LDAP::TagNumber::DelRequest), request.dn);
    }

    template<typename Writer, typename Filter>
    void write_data(Writer& writer, LDAP::SearchRequest<Filter> const& request) {
        writer.write_sequence(BER::Identifier(TagClass::Application, Encoding::Constructed, LDAP::TagNumber::SearchRequest),
            request.base_object, request.scope, request.deref_aliases, request.size_limit, request.time_limit, request.types_only, request.filter, request.attributes);
    }

    template<typename Writer>
    void write_data(Writer& writer, std::initializer_list<LDAP::Control> const& controls) {
        writer.write_sequence_container(BER::Identifier(TagClass::ContextSpecific, Encoding::Constructed, LDAP::TagNumber::Controls), controls);
    }

    template<typename Writer>
    void write_data(Writer& writer, LDAP::Control const& control) {
        if (control.control_value) {
            writer.write_sequence(control.control_type, control.criticality, *control.control_value);
        } else {
            writer.write_sequence(control.control_type, control.criticality);
        }
    }

}
