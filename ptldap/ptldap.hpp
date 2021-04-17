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

namespace BER
{
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
        static pair<Bool*, size_t> parse(string_view data)
        {
            size_t offset = 0;
            uint8_t type = data.data()[offset++];
            uint8_t size = data.data()[offset++];
            uint8_t payload = data.data()[offset++];

            if ((Type)type != Type::Bool) {
                return pair<Bool*, size_t>(nullptr, 0);
            }

            return pair<Bool*, size_t>(new Bool(!!payload), offset);
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
        static pair<Integer*, size_t> parse(string_view data)
        {
            size_t offset = 0;
            uint8_t type = data.data()[offset++];
            uint8_t size = data.data()[offset++];

            if ((Type)type != Type::Integer && (Type)type != Type::Enum) {
                return pair<Integer*, size_t>(nullptr, 0);
            }

            size_t value = 0;
            for (size_t i = 0; i < size; i++)
            {
                value += data.data()[offset++] << (i*8);
            }
            return pair<Integer*, size_t>(new Integer(value), offset);
        }
    };

    template <typename T>
    class Enum : public Integer
    {
    public:
        explicit Enum(T value) : Integer(static_cast<uint32_t>(value), Type::Enum) {}
        static pair<Enum*, size_t> parse(string data)
        {
            size_t offset = 0;
            uint8_t type = data.c_str()[offset++];
            uint8_t size = data.c_str()[offset++];

            if ((Type)type != Type::Enum) {
                return pair<Enum*, size_t>(nullptr, 0);
            }

            if (sizeof(T) < size) {
                return pair<Enum*, size_t>(nullptr, 0);
            }

            size_t value = 0;
            for (size_t i = 0; i < sizeof(T); i++)
            {
                value += data.c_str()[offset++] << (i*8);
            }
            return pair<Enum*, size_t>(new Enum<T>((T)value), offset);
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
        static pair<String*, size_t> parse(string_view data)
        {
            size_t offset = 0;
            uint8_t type = data.data()[offset++];
            uint8_t size = data.data()[offset++];
            string payload;

            if ((Type)type != Type::String) {
                return pair<String*, size_t>(nullptr, 0);
            }

            for(size_t i = 0; i < size; i++) {
                payload += data.data()[offset++];
            }
            return pair<String*, size_t>(new String(payload), offset);
        }
    };

    // This implementation is inexact
    class SimpleAuth : public String
    {
    public:
        explicit SimpleAuth(uint8_t len, const char *value) : String(len, value, Type::SimpleAuth) {}
        explicit SimpleAuth(string value) : String(std::move(value), Type::SimpleAuth) {}
        static pair<SimpleAuth*, size_t> parse(string_view data)
        {
            size_t offset = 0;
            uint8_t type = data.data()[offset++];
            uint8_t size = data.data()[offset++];
            string payload;

            if ((Type)type != Type::SimpleAuth) {
                return pair<SimpleAuth*, size_t>(nullptr, 0);
            }

            for(size_t i = 0; i < size; i++) {
                payload += data.data()[offset++];
            }
            return pair<SimpleAuth*, size_t>(new SimpleAuth(payload), offset);
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
        static pair<Element*, size_t> parse(string_view data) {
            Type type = static_cast<Type>(data[0]);
            switch(type) {
                case Type::Bool: {
                    auto res = Bool::parse(data);
                    return pair<Element*, size_t>(static_cast<Element *>(res.first), res.second);
                }
                case Type::Integer: {
                    auto res = Integer::parse(data);
                    return pair<Element*, size_t>(static_cast<Element *>(res.first), res.second);
                }
                case Type::String: {
                    auto res = String::parse(data);
                    return pair<Element*, size_t>(static_cast<Element *>(res.first), res.second);
                }
                case Type::Enum: {
                    auto res = Integer::parse(data);
                    return pair<Element*, size_t>(static_cast<Element *>(res.first), res.second);
                }
                case Type::Attribute: {
                    auto res = String::parse(data);
                    return pair<Element*, size_t>(static_cast<Element *>(res.first), res.second);
                }
                case Type::SimpleAuth: {
                    auto res = SimpleAuth::parse(data);
                    return pair<Element*, size_t>(static_cast<Element *>(res.first), res.second);
                }
                default:
                    return pair<Element*, size_t>(nullptr, 0);
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
        vector<BER::Element*> elements;

    public:
        explicit Op(Protocol::Type type) : type(type) {}
        Op &addElement(BER::Element* element)
        {
            elements.push_back(element);
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
        static pair<Op*, size_t> parse(string_view data) {
            size_t offset = 0;
            Protocol::Type type = static_cast<Protocol::Type>(data.data()[offset++]);
            uint8_t size = data.data()[offset++];

            auto op = new Op(type);
            while (offset < size + offset) {
                auto element_str = data.substr(offset);
                auto res = BER::ElementBuilder::parse(element_str);
                op->addElement(res.first);
                offset += res.second;
            }
            return pair<Op*, size_t>(op, 0);
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
            this->op.addElement(&this->version) // Supported LDAP version
                .addElement(&this->name)
                .addElement(&this->password);
        }
        BindRequest(BER::String* name, BER::SimpleAuth* password)
                : BaseMsg(Protocol::Type::BindRequest),
                  name(std::move(*name)),
                  password(std::move(*password))
        {
            this->op.addElement(&this->version) // Supported LDAP version
                    .addElement(&this->name)
                    .addElement(&this->password);
        }
        static BindRequest* parse(string data) {
            size_t offset = 0;

            auto ber_version = BER::ElementBuilder::parse(data.substr(offset));
            auto version = static_cast<BER::Integer*>(ber_version.first);
            offset += ber_version.second;

            auto ber_name = BER::ElementBuilder::parse(data.substr(offset));
            auto name = static_cast<BER::String*>(ber_name.first);
            offset += ber_name.second;

            auto ber_password = BER::ElementBuilder::parse(data.substr(offset));
            auto password = static_cast<BER::SimpleAuth*>(ber_password.first);
            offset += ber_password.second;

            auto bindRequest = new BindRequest(name, password);
            return bindRequest;
        }
    };

//     class BindResponse : public BaseMsg
//     {
//     public:
//         BindResponse(Protocol::ResultCode resultCode) : BaseMsg(Protocol::Type::BindResponse)
//         {
//             this->op.addElement(new BER::Integer<uint8_t>(static_cast<unsigned char>(resultCode)));
//         }
//
//         static parse(string msg)
//         {
//             // size_t i = 0;
//             // while(i < msg.size)
//             // {
//             //     void* ptr = &msg.c_str[i];
//             //     (BER::Integer<uint8_t>*)ptr
//             // }
//         }
//     };

    class SearchRequest : public BaseMsg
    {
        BER::String baseObject;
        BER::Enum<Protocol::SearchRequest::Scope> scope;
        BER::Enum<Protocol::SearchRequest::DerefAliases> derefAliases;
        BER::Integer sizeLimit;
        BER::Integer timeLimit;
        BER::Bool typesOnly;
        BER::Filter filter;
        BER::Attribute attribute;
    public:
        SearchRequest(string baseObject,
                      string filterType,
                      string filterValue,
                      string attribute,
                      Protocol::SearchRequest::Scope scope = Protocol::SearchRequest::Scope::SingleLevel,
                      Protocol::SearchRequest::DerefAliases derefAliases = Protocol::SearchRequest::DerefAliases::NeverDerefAliases,
                      bool typesOnly = false)
        : BaseMsg(Protocol::Type::SearchRequest),
          baseObject(BER::String(std::move(baseObject))),
          scope(BER::Enum<Protocol::SearchRequest::Scope>(scope)),
          derefAliases(BER::Enum<Protocol::SearchRequest::DerefAliases>(derefAliases)),
          sizeLimit(BER::Integer(0)),
          timeLimit(BER::Integer(0)),
          typesOnly(BER::Bool(typesOnly)),
          filter(BER::Filter(std::move(filterType), std::move(filterValue))),
          attribute(BER::Attribute(std::move(attribute)))
        {
            this->op
                .addElement(&this->baseObject)
                .addElement(&this->scope)
                .addElement(&this->derefAliases)
                .addElement(&this->sizeLimit)
                .addElement(&this->timeLimit)
                .addElement(&this->typesOnly)
                .addElement(&this->filter)
                .addElement(&this->attribute);
        }

//        static SearchRequest parse(string msg) {
//            size_t offset = 0;
//
//        }
    };
}