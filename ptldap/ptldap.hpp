// For more inspiration, see https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-ldap.c

#include <string>
#include <type_traits>
#include <utility>
#include <vector>
#include <sstream>
#include <memory>
#include <iostream>
#include <cstring>

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
        static Bool* parse(string data)
        {
            size_t offset = 0;
            uint8_t type = data.c_str()[offset++];
            uint8_t size = data.c_str()[offset++];
            uint8_t payload = data.c_str()[offset++];

            if ((Type)type != Type::Bool) {
                return nullptr;
            }

            return new Bool(!!payload);
        }
    };

    template <typename T>
    class Integer : public Element
    {
    public:
        T value;
        explicit Integer(T value, Type type = Type::Integer) : Element(type), value(value) {}
        ostringstream &append(ostringstream &oss) final
        {
            oss << (char)this->type;
            oss << (char)sizeof(T);
            // TODO: do something less stupid
            for(size_t i = 0; i < sizeof(T); i++) {
                oss << (char)((uint8_t*)&this->value)[i];
            }
            return oss;
        }
        static Integer* parse(string data)
        {
            size_t offset = 0;
            uint8_t type = data.c_str()[offset++];
            uint8_t size = data.c_str()[offset++];

            if ((Type)type != Type::Integer) {
                return nullptr;
            }

            if (sizeof(T) < size) {
                return nullptr;
            }

            size_t value = 0;
            for (size_t i = 0; i < sizeof(T); i++)
            {
                value += data.c_str()[offset++] << (i*8);
            }
            return new Integer<T>((T)value);
        }
    };

    template <typename T>
    class Enum : public Integer<T>
    {
    public:
        explicit Enum(T value) : Integer<T>(value, Type::Enum) {}
        static Enum* parse(string data)
        {
            size_t offset = 0;
            uint8_t type = data.c_str()[offset++];
            uint8_t size = data.c_str()[offset++];

            if ((Type)type != Type::Enum) {
                return nullptr;
            }

            if (sizeof(T) < size) {
                return nullptr;
            }

            size_t value = 0;
            for (size_t i = 0; i < sizeof(T); i++)
            {
                value += data.c_str()[offset++] << (i*8);
            }
            return new Enum<T>((T)value);
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
        static String* parse(string data)
        {
            size_t offset = 0;
            uint8_t type = data.c_str()[offset++];
            uint8_t size = data.c_str()[offset++];
            string payload;

            if ((Type)type != Type::Enum) {
                return nullptr;
            }

            for(size_t i = offset; offset < data.size(); i++) {
                payload += data.c_str()[i];
            }
            return new String(payload);
        }
    };

    // This implementation is inexact
    class SimpleAuth : public String
    {
    public:
        explicit SimpleAuth(uint8_t len, const char *value) : String(len, value, Type::SimpleAuth) {}
        explicit SimpleAuth(string value) : String(std::move(value), Type::SimpleAuth) {}
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
        vector<BER::Element *> elements;

    public:
        explicit Op(Protocol::Type type) : type(type) {}
        Op &addElement(BER::Element *element)
        {
            elements.push_back(element);
            return *this;
        }
        string str()
        {
            ostringstream inside;
            for (auto element : this->elements)
            {
                element->append(inside);
            }
            ostringstream oss;
            oss << (char)this->type;
            oss << (char)inside.str().length();
            oss << inside.str();
            return oss.str();
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
            auto _id = BER::Integer<uint8_t>(this->id).str();
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
        BER::Integer<uint8_t> version = BER::Integer<uint8_t>(0x03);
        BER::String name;
        BER::String password;
    public:
        BindRequest(string name, string password)
        : BaseMsg(Protocol::Type::BindRequest),
          name(BER::String(std::move(name))),
          password(BER::SimpleAuth(std::move(password)))
        {
            this->op.addElement(&this->version) // Supported LDAP version
                .addElement(&this->name)
                .addElement(&this->password);
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
        BER::Integer<uint8_t> sizeLimit;
        BER::Integer<uint8_t> timeLimit;
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
          sizeLimit(BER::Integer<uint8_t>(0)),
          timeLimit(BER::Integer<uint8_t>(0)),
          typesOnly(BER::Bool(typesOnly)),
          filter(BER::Filter(std::move(filterType), std::move(filterValue))),
          attribute(BER::Attribute(std::move(attribute)))
        {
            this->op.addElement(&this->baseObject)
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