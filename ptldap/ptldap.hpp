// For more inspiration, see https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-ldap.c

#include <string>
#include <type_traits>
#include <utility>
#include <vector>
#include <sstream>
#include <memory>
#include <iostream>
#include <cstring>

#include "string_view.hpp"
using namespace nonstd::literals;
using namespace nonstd;

using namespace std;

template<typename TO, typename FROM>
static unique_ptr<TO> static_unique_pointer_cast (unique_ptr<FROM>&& old){
    // conversion: unique_ptr<FROM>->FROM*->TO*->unique_ptr<TO>
    return unique_ptr<TO>{static_cast<TO*>(old.release())};
}

namespace BER
{
    template <typename T>
    struct ParseResult {
        unique_ptr<T> value;
        size_t length;
    };

    enum class Type : uint8_t
    {
        // Base types
        Bool = 0x01,
        Integer = 0x02,
        String = 0x04,
        Enum = 0x0a,

        Attribute = 0x30,

        // Authentications
        SimpleAuth = 0x80,
        SASL,

        // Filters
        And = 0xA0,
        Or,
        Not,
        EqualityMatch,
        Substrings,
        GreaterOrEqual,
        LessOrEqual,
        Present,
        ApproxMatch,
        ExtensibleMatch,
    };

    enum class MatchingRuleAssertion
    {
        MatchingRule = 0x81,
        Type,
        MatchValue,
        DnAttributes,
    };


    class Element
    {
    public:
        Type type;
        explicit Element(Type type) : type(type) {}
        string str()
        {
            ostringstream oss;
            this->append(oss);
            return oss.str();
        }
        virtual ostringstream &append(ostringstream &oss) = 0;
        template <typename T>
        static unique_ptr<T> as(unique_ptr<Element> element) {
            return static_unique_pointer_cast<T>(move(element));
        }
        template <typename T>
        static ParseResult<T> parse(string_view data) {};
    };

    class Bool : public Element
    {
        Bool() : Element(Type::Bool), value(false) {}
    public:
        bool value;

        explicit Bool(bool value) : Element(Type::Bool), value(value) {}
        ostringstream &append(ostringstream &oss) final
        {
            oss << (char)this->type;
            oss << (char)sizeof(bool);
            oss << (char)this->value;
            return oss;
        }
        template <typename T=Bool>
        static ParseResult<T> parse(string_view data)
        {
            size_t offset = 0;
            uint8_t type = data[offset++];
            uint8_t size = data[offset++];
            uint8_t payload = data[offset++];

            if ((Type)type != Type::Bool) {
                return ParseResult<T> {nullptr, 0};
            }

            return ParseResult<T> {make_unique<Bool>(!!payload), offset };
        }
    };

    class Integer : public Element
    {
    public:
        uint32_t value;
        explicit Integer(uint32_t value, Type type = Type::Integer) : Element(type), value(value) {}
        ostringstream &append(ostringstream &oss) final
        {
            uint8_t size = 1;
            if (value != 0) {
                size = (int)log2(value - 1) / 8 + 1;
            }

            oss << (char)this->type;
            oss << (char)size;
            for(size_t i = 0; i < size; i++) {
                auto shift = ((size-1-i)*8);
                uint8_t byte = (value >> shift) & 0xff;
                oss << (uint8_t)byte;
            }
            return oss;
        }
        template <typename T=Integer>
        static ParseResult<T> parse(string_view data)
        {
            size_t offset = 0;
            uint8_t type = data.data()[offset++];
            uint8_t size = data.data()[offset++];

            if ((Type)type != Type::Integer && (Type)type != Type::Enum) {
                return ParseResult<T> {nullptr, 0};
            }

            size_t value = 0;
            for (size_t i = 0; i < size; i++)
            {
                value += data.data()[offset++] << (i*8);
            }
            return ParseResult<T> {std::make_unique<Integer>(value), offset};
        }
    };

    template <typename E>
    class Enum : public Integer
    {
    public:
        explicit Enum(E value) : Integer(static_cast<uint32_t>(value), Type::Enum) {}

        template <typename T=Enum<E>>
        static ParseResult<T> parse(string data)
        {
            size_t offset = 0;
            uint8_t type = data[offset++];
            uint8_t size = data[offset++];

            if ((Type)type != Type::Enum) {
                return ParseResult<T> {nullptr, 0};
            }

            if (sizeof(E) < size) {
                return ParseResult<T> {nullptr, 0};
            }

            size_t value = 0;
            for (size_t i = 0; i < size; i++)
            {
                value += data[offset++] << (i*8);
            }
            return ParseResult<T> {make_unique<T>((E)value), offset};
        }
    };

    class String : public Element
    {
    public:
        string value;
        explicit String(uint8_t len, const char *value, Type type = Type::String) : Element(type),
                                                                                    value(string(value, len)) {}
        explicit String(string value, Type type = Type::String) : Element(type), value(std::move(value)) {}
        ostringstream &append(ostringstream &oss) final
        {
            oss << (char)this->type;
            oss << (char)value.length();
            oss << this->value;
            return oss;
        }
        template <typename T=String>
        static ParseResult<T> parse(string_view data)
        {
            size_t offset = 0;
            uint8_t type = data[offset++];
            uint8_t size = data[offset++];
            string payload;

            if ((Type)type != Type::String) {
                return ParseResult<T> {nullptr, 0};
            }

            for(size_t i = 0; i < size; i++) {
                payload += data[offset++];
            }
            return ParseResult<T> {make_unique<T>(payload), offset};
        }
    };

    // This implementation is inexact
    class SimpleAuth : public String
    {
    public:
        explicit SimpleAuth(uint8_t len, const char *value) : String(len, value, Type::SimpleAuth) {}
        explicit SimpleAuth(string value) : String(std::move(value), Type::SimpleAuth) {}

        template <typename T>
        static ParseResult<T> parse(string_view data)
        {
            size_t offset = 0;
            uint8_t type = data[offset++];
            uint8_t size = data[offset++];
            string payload;

            if ((Type)type != Type::SimpleAuth) {
                return ParseResult<T> {nullptr, 0};
            }

            for(size_t i = 0; i < size; i++) {
                payload += data[offset++];
            }
            return ParseResult<T> {make_unique<T>(payload), offset};
        }
    };

    // This implementation is inexact, only support simple extensibleMatch
    class Filter : public Element
    {
    protected:
        string filterType;
        string matchValue;

    public:
        explicit Filter(uint8_t filterTypeLen, const char *filterType, uint8_t matchValueLen, const char *matchValue, Type type = Type::ExtensibleMatch) : Element(type),
                                                                                                                                                           filterType(string(filterType, filterTypeLen)),
                                                                                                                                                           matchValue(string(matchValue, matchValueLen)) {}
        explicit Filter(string filterType, string matchValue, Type type = Type::ExtensibleMatch) : Element(type), filterType(std::move(filterType)), matchValue(std::move(matchValue)) {}
        ostringstream &append(ostringstream &oss) final
        {
            auto _filterType = String(this->filterType, static_cast<Type>(MatchingRuleAssertion::Type));
            auto _matchValue = String(this->matchValue, static_cast<Type>(MatchingRuleAssertion::MatchValue));
            auto extensibleMatchLength = _filterType.str().length() + _matchValue.str().length();

            oss << (char)this->type;
            oss << (char)extensibleMatchLength;
            oss << _filterType.str();
            oss << _matchValue.str();
            return oss;
        }
    };

    // This implementation is inexact
    class Attribute : public Element
    {
    protected:
        string value;

    public:
        explicit Attribute(uint8_t attributeLen, const char *attribute) : Element(Type::Attribute),
                                                                          value(string(attribute, attributeLen)) {}
        explicit Attribute(string value) : Element(Type::Attribute), value(value) {}
        ostringstream &append(ostringstream &oss) final
        {
            auto attribute = String(this->value);

            oss << (char)this->type;
            oss << (char)attribute.str().length();
            oss << attribute.str();
            return oss;
        }
    };

    class ElementBuilder
    {
    public:
        ElementBuilder() = default;
        template <typename T=Element>
        static ParseResult<T> parse(string_view data) {
            Type type = static_cast<Type>(data[0]);
            switch(type) {
                case Type::Bool: {
                    return Bool::parse<T>(data);
                }
                case Type::Integer: {
                    return Integer::parse<T>(data);
//                    auto res = Integer::parse(data);
//                    return pair<Element*, size_t>(static_cast<Element *>(res.first), res.second);
                }
                case Type::String: {
                    return String::parse<T>(data);
//                    auto res = String::parse(data);
//                    return pair<Element*, size_t>(static_cast<Element *>(res.first), res.second);
                }
                case Type::Enum: {
                    return Integer::parse<T>(data);
//                    auto res = Integer::parse(data);
//                    return pair<Element*, size_t>(static_cast<Element *>(res.first), res.second);
                }
                case Type::Attribute: {
                    return String::parse<T>(data);
//                    auto res = String::parse(data);
//                    return pair<Element*, size_t>(static_cast<Element *>(res.first), res.second);
                }
                case Type::SimpleAuth: {
                    return SimpleAuth::parse<T>(data);
//                    auto res = SimpleAuth::parse(data);
//                    return pair<Element*, size_t>(static_cast<Element *>(res.first), res.second);
                }
                default:
                    return ParseResult<T> {nullptr, 0};
            }
        }
    };
}

namespace LDAP
{
    const uint8_t Header = 0x30;

    namespace Protocol
    {
        enum class Type : uint8_t
        {
            BindRequest = 0x60,
            BindResponse,
            UnbindRequest,
            SearchRequest,
            SearchResultEntry,
            SearchResultDone,
            SearchResultReference,
            ModifyRequest,
            ModifyResponse,
            AddRequest,
            AddResponse,
            DelRequest,
            DelResponse,
            ModifyDNRequest,
            ModifyDNResponse,
            CompareRequest,
            CompareResponse,
            AbandonRequest,
            ExtendedRequest,
            ExtendedResponse,
        };

        enum class ResultCode : uint8_t
        {
            Success = 0,
            OperationsError = 1,
            ProtocolError = 2,
            TimeLimitExceeded = 3,
            SizeLimitExceeded = 4,
            CompareFalse = 5,
            CompareTrue = 6,
            AuthMethodNotSupported = 7,
            StrongAuthRequired = 8,
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
            Other = 80,
            Canceled = 118,
            NoSuchOperation = 119,
            TooLate = 120,
            CannotCancel = 121,
        };

        namespace SearchRequest
        {
            enum class Scope : uint8_t
            {
                BaseObject,
                SingleLevel,
                WholeSubtree
            };

            enum class DerefAliases : uint8_t
            {
                NeverDerefAliases,
                DerefInSearching,
                DerefFindingBaseObj,
                DerefAlways
            };
        }

        enum class FilterType
        {
            And = 0xa0,      // SET SIZE (1..MAX) OF filter Filter,
            Or,              // SET SIZE (1..MAX) OF filter Filter,
            Not,             // Filter,
            EqualityMatch,   // AttributeValueAssertion,
            Substrings,      // SubstringFilter,
            GreaterOrEqual,  // AttributeValueAssertion,
            LessOrEqual,     // AttributeValueAssertion,
            Present,         // AttributeDescription,
            ApproxMatch,     // AttributeValueAssertion,
            ExtensibleMatch, // MatchingRuleAssertion,
        };
    }

    class Op
    {
    private:
        Protocol::Type type;
        vector<unique_ptr<BER::Element>> elements;

    public:
        explicit Op(Protocol::Type type) : type(type) {}
        Op &addElement(unique_ptr<BER::Element> element)
        {
            elements.push_back(move(element));
            return *this;
        }
        string str()
        {
            ostringstream inside;
            for (auto& element : this->elements)
            {
                element->append(inside);
            }
            ostringstream oss;
            oss << (char)this->type;
            oss << (char)inside.str().length();
            oss << inside.str();
            return oss.str();
        }
        template <typename T=Op>
        static BER::ParseResult<Op> parse(string_view data) {
            size_t offset = 0;
            auto type = static_cast<Protocol::Type>(data[offset++]);
            uint8_t size = data[offset++];

            auto op = new Op(type);
            while (offset < size + offset) {
                auto element_str = data.substr(offset);
                auto res = BER::ElementBuilder::parse(element_str);
                op->addElement(move(res.value));
                offset += res.length;
            }
            return BER::ParseResult<Op> {make_unique<Op>(op), offset};
        }
    };

    class Msg
    {
        uint8_t id;
        Op *op;

    public:
        Msg(uint8_t id, Op *op) : id(id), op(op) {}
        string str()
        {
            auto _id = BER::Integer(this->id).str();
            auto _op = this->op->str();
            uint8_t msgSize = _id.length() + _op.length();

            ostringstream oss;
            oss << Header;
            oss << msgSize;

            oss << _id;

            oss << _op;
            return oss.str();
        }
    };

    class MsgBuilder
    {
    public:
        #if (__cplusplus >= 201703L)
        inline static uint8_t id;
        #else
        static uint8_t id;
        #endif

        MsgBuilder() = default;
        static unique_ptr<Msg> build(Op *op) { return std::unique_ptr<Msg>(new Msg(id++, op)); }
        static void reset_id() { id = 1; }
    };

    class BaseMsg
    {
    protected:
        Op op;
        unique_ptr<Msg> msg;
        explicit BaseMsg(Protocol::Type type) : op(Op(type)), msg(LDAP::MsgBuilder::build(&this->op)) {}

    public:
        string str() { return this->msg->str(); }
    };

    class BindRequest : public BaseMsg
    {
    public:
        BER::Integer version = BER::Integer(0x03);
        BER::String name;
        BER::SimpleAuth password;
        BindRequest(string name, string password)
        : BaseMsg(Protocol::Type::BindRequest),
          name(BER::String(std::move(name))),
          password(BER::SimpleAuth(std::move(password)))
        {
            this->op.addElement(make_unique<BER::Integer>(this->version)) // Supported LDAP version
                .addElement(make_unique<BER::String>(this->name))
                .addElement(make_unique<BER::SimpleAuth>(this->password));
        }
        BindRequest(unique_ptr<BER::String> name, unique_ptr<BER::SimpleAuth> password)
        : BaseMsg(Protocol::Type::BindRequest),
          name(std::move(*name)),
          password(std::move(*password))
        {
            this->op.addElement(make_unique<BER::Integer>(this->version)) // Supported LDAP version
                    .addElement(make_unique<BER::String>(this->name))
                    .addElement(make_unique<BER::SimpleAuth>(this->password));
        }
        static BER::ParseResult<BindRequest> parse(string data) {
            size_t offset = 0;

            // Only used to validate offset
            auto version_parsed = BER::ElementBuilder::parse<BER::Integer>(data.substr(offset));
            auto ber_version = move(version_parsed.value);
            offset += version_parsed.length;

            auto name_parsed = BER::ElementBuilder::parse<BER::String>(data.substr(offset));
            offset += name_parsed.length;

            auto password_parsed = BER::ElementBuilder::parse<BER::SimpleAuth>(data.substr(offset));
            offset += password_parsed.length;

            auto bind_request = make_unique<BindRequest>(move(name_parsed.value), move(password_parsed.value));
            return BER::ParseResult<BindRequest> {move(bind_request), offset};
        }
    };

     class BindResponse : public BaseMsg
     {
         BER::Enum<uint8_t> resultCode;
         BER::String matched_dn;
         BER::String error_message;
     public:
         BindResponse(Protocol::ResultCode resultCode, string matched_dn = "", string error_message = "")
         : BaseMsg(Protocol::Type::BindResponse),
           resultCode((uint8_t)resultCode),
           matched_dn(std::move(matched_dn)),
           error_message(std::move(error_message))
         {
             this->op.addElement(make_unique<BER::Enum<uint8_t>>(this->resultCode))
                     .addElement(make_unique<BER::String>(this->matched_dn))
                     .addElement(make_unique<BER::String>(this->error_message));
         }
         BindResponse(unique_ptr<BER::Enum<uint8_t>> resultCode, unique_ptr<BER::String> matched_dn, unique_ptr<BER::String> error_message)
         : BaseMsg(Protocol::Type::BindResponse),
           resultCode(std::move(*resultCode)),
           matched_dn(std::move(*matched_dn)),
           error_message(std::move(*error_message))
         {
             this->op.addElement(make_unique<BER::Enum<uint8_t>>(this->resultCode))
                     .addElement(make_unique<BER::String>(this->matched_dn))
                     .addElement(make_unique<BER::String>(this->error_message));
         }
         static unique_ptr<BindResponse> parse(string data)
         {
             size_t offset = 0;


             auto res = BER::ElementBuilder::parse(data.substr(offset));
             auto ber_result_code = res.value->as<BER::Enum<uint8_t>>(move(res.value));
             offset += res.length;

             res = BER::ElementBuilder::parse(data.substr(offset));
             auto ber_matched_dn = res.value->as<BER::String>(move(res.value));
             offset += res.length;

             res = BER::ElementBuilder::parse(data.substr(offset));
             auto ber_error_message = res.value->as<BER::String>(move(res.value));
             offset += res.length;

             return make_unique<BindResponse>(move(ber_result_code), move(ber_matched_dn), move(ber_error_message));
         }
     };

//    class SearchRequest : public BaseMsg
//    {
//        BER::String baseObject;
//        BER::Enum<Protocol::SearchRequest::Scope> scope;
//        BER::Enum<Protocol::SearchRequest::DerefAliases> derefAliases;
//        BER::Integer sizeLimit;
//        BER::Integer timeLimit;
//        BER::Bool typesOnly;
//        BER::Filter filter;
//        BER::Attribute attribute;
//    public:
//        SearchRequest(string baseObject,
//                      string filterType,
//                      string filterValue,
//                      string attribute,
//                      Protocol::SearchRequest::Scope scope = Protocol::SearchRequest::Scope::SingleLevel,
//                      Protocol::SearchRequest::DerefAliases derefAliases = Protocol::SearchRequest::DerefAliases::NeverDerefAliases,
//                      bool typesOnly = false)
//        : BaseMsg(Protocol::Type::SearchRequest),
//          baseObject(BER::String(std::move(baseObject))),
//          scope(BER::Enum<Protocol::SearchRequest::Scope>(scope)),
//          derefAliases(BER::Enum<Protocol::SearchRequest::DerefAliases>(derefAliases)),
//          sizeLimit(BER::Integer(0)),
//          timeLimit(BER::Integer(0)),
//          typesOnly(BER::Bool(typesOnly)),
//          filter(BER::Filter(std::move(filterType), std::move(filterValue))),
//          attribute(BER::Attribute(std::move(attribute)))
//        {
//            this->op
//                .addElement(&this->baseObject)
//                .addElement(&this->scope)
//                .addElement(&this->derefAliases)
//                .addElement(&this->sizeLimit)
//                .addElement(&this->timeLimit)
//                .addElement(&this->typesOnly)
//                .addElement(&this->filter)
//                .addElement(&this->attribute);
//        }
//
//        static SearchRequest parse(string msg) {
//            size_t offset = 0;
//
//        }
//    };
}