// Lightweight Directory Access Protocol (LDAP): The Protocol
// https://datatracker.ietf.org/doc/html/rfc4511

// LDAPv3 Wire Protocol Reference
// https://ldap.com/ldapv3-wire-protocol-reference/

#include "ber.hpp"

namespace LDAP {

    enum class ResultCode {
        Success = 0,
        OperationsError = 1,
        ProtocolError = 2,
        TimeLimitExceeded = 3,
        SizeLimitExceeded = 4,
        CompareFalse = 5,
        CompareTrue = 6,
        AuthMethodNotSupported = 7,
        StrongerAuthRequired = 8,
        Referral = 10,
        AdminLimitExceeded = 11,
        UnavailableCriticalExtension = 12,
        ConfidentialityRequired = 13,
        SaslBindInProgress = 14,
        NoSuchAttribute = 16,
        UndefinedAttributeType = 17,
        InappropriateMatching = 18,
        ConstraintViolation = 19,
        AttributeOrValueExists = 20,
        InvalidAttributeSyntax = 21,
        NoSuchObject = 32,
        AliasProblem = 33,
        InvalidDNSyntax = 34,
        AliasDereferencingProblem = 36,
        InappropriateAuthentication = 48,
        InvalidCredentials = 49,
        InsufficientAccessRights = 50,
        Busy = 51,
        Unavailable = 52,
        UnwillingToPerform = 53,
        LoopDetect = 54,
        NamingViolation = 64,
        ObjectClassViolation = 65,
        NotAllowedOnNonLeaf = 66,
        NotAllowedOnRDN = 67,
        EntryAlreadyExists = 68,
        ObjectClassModsProhibited = 69,
        AffectsMultipleDSAs = 71,
        Other = 80
    };

    constexpr auto ldapoid = BER::octet_string;

    constexpr auto ldapdn = BER::octet_string;

    constexpr auto ldap_string = BER::octet_string;

    constexpr auto uri = ldap_string;

    constexpr auto referral = BER::sequence_of(uri);

    constexpr auto message_id = BER::integer;

    constexpr auto ldap_result = BER::sequence(
        /*BER::enumerated<ResultCode>, */ldapdn, ldap_string, BER::optional(referral.context_specific(3)));

    enum class AuthenticationChoice {
        simple = 0,
        sasl = 3,
    };
    constexpr auto authentication_choice = BER::choice(
        BER::octet_string.context_specific(AuthenticationChoice::simple)
    );

    constexpr auto bind_request = BER::sequence(
        BER::integer, ldapdn, authentication_choice).application(0);

    constexpr auto control = BER::sequence(
        ldapoid, BER::boolean, BER::optional(BER::octet_string));

    constexpr auto controls = BER::sequence_of(control);

    constexpr auto message = BER::sequence(
        message_id, bind_request, BER::optional(controls));

    constexpr auto compare_response = ldap_result.application(15);

    constexpr auto abandon_request = message_id.application(16);

    constexpr auto extended_request = BER::sequence(
        ldapoid.context_specific(0),
        BER::optional(BER::octet_string.context_specific(1))
    ).template application(23);

    constexpr auto extended_response = BER::sequence(
        // TODO: COMPONENTS OF LDAPResult,
        BER::optional(ldapoid.context_specific(10)),
        BER::optional(BER::octet_string.context_specific(11))
    ).application(24);

    constexpr auto intermediate_response = BER::sequence(
        BER::optional(ldapoid.context_specific(0)),
        BER::optional(BER::octet_string.context_specific(1))
    ).application(25);

}
