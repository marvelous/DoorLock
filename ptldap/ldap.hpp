// Lightweight Directory Access Protocol (LDAP): The Protocol
// https://datatracker.ietf.org/doc/html/rfc4511

// LDAPv3 Wire Protocol Reference
// https://ldap.com/ldapv3-wire-protocol-reference/

#include "ber.hpp"

namespace LDAP
{

    enum class TagNumber {
        DelRequest = 10,
    };

    struct DelRequest {
        std::string_view dn;
    };

    struct Control {
        std::string_view control_type;
        bool criticality;
        std::optional<std::string_view> control_value;
    };

    template<typename BERReader>
    struct Controls {

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
    struct Message {

        int32_t message_id;
        BER::Identifier identifier;
        BERReader ber;

        bool is_tag_number(TagNumber tag_number) {
            return identifier.tag_number == BER::TagNumber(tag_number);
        }

        std::optional<DelRequest> read_del_request() {
            OPT_REQUIRE(is_tag_number(TagNumber::DelRequest));
            auto dn = OPT_TRY(ber.read_octet_string(identifier));
            return DelRequest{dn};
        }

        std::optional<Controls<BERReader>> read_controls() {
            auto identifier = OPT_TRY(ber.read_identifier());
            OPT_REQUIRE(identifier.tag_class == BER::TagClass::ContextSpecific);
            OPT_REQUIRE(identifier.encoding == BER::Encoding::Constructed);
            OPT_REQUIRE(identifier.tag_number == 0);

            auto sequence = OPT_TRY(ber.read_sequence(identifier));
            return Controls<BERReader>{std::move(sequence)};
        }

    };

    template<typename BERReader>
    struct Reader {

        BERReader ber;

        std::optional<Message<BERReader>> read_message() {
            auto sequence = OPT_TRY(ber.read_sequence());

            auto message_id = OPT_TRY(sequence.template read_integer<int32_t>());
            OPT_REQUIRE(message_id >= 0);

            auto identifier = OPT_TRY(sequence.read_identifier());
            OPT_REQUIRE(identifier.tag_class == BER::TagClass::Application);

            return Message<BERReader>{message_id, identifier, std::move(sequence)};
        }

    };

    template<typename BERReader>
    auto make_reader(BERReader ber) {
        return Reader<BERReader>{std::move(ber)};
    }

}
