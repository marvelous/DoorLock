#include <string>
#include <utility>
#include <vector>
#include <sstream>
#include <memory>
#include <iostream>
#include <cstring>

using namespace std;


namespace BER {
    enum class Type : uint8_t {
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

    enum class MatchingRuleAssertion {
        MatchingRule = 0x81,
        Type,
        MatchValue,
        DnAttributes,
    };

    class Element {
    public:
        Type type;
        explicit Element(Type type) : type(type) {}
        string str() {
            ostringstream oss;
            this->append(oss);
            return oss.str();
        }
        virtual ostringstream& append(ostringstream& oss) = 0;
    };

    class Bool : public Element {
        bool value;
    public:
        explicit Bool(bool value) : Element(Type::Bool), value(value) {}
        ostringstream& append(ostringstream& oss) final {
            oss << (char)this->type;
            oss << (char)sizeof(bool);
            oss << (char)this->value;
            return oss;
        }
    };

    template<typename T>
    class Integer : public Element {
         T value;
    public:
        explicit Integer(T value, Type type = Type::Integer) : Element(type), value(value) {}
        ostringstream& append(ostringstream& oss) final {
            oss << (char)this->type;
            oss << (char)sizeof(T);
            oss << (char)this->value;
            return oss;
        }
    };
    template<typename T>
    class Enum : public Integer<T> {
    public:
        explicit Enum(T value) : Integer<T>(value, Type::Enum) {}
    };

    class String : public Element {
    protected:
        string value;
    public:
        explicit String(uint8_t len, const char* value, Type type = Type::String) :
            Element(type),
            value(string(value, len)) {}
        explicit String(string value, Type type = Type::String) : Element(type), value(std::move(value)) {}
        ostringstream& append(ostringstream& oss) final {
            oss << (char)this->type;
            oss << (char)value.length();
            oss << this->value;
            return oss;
        }
    };

    // This implementation is inexact
    class SimpleAuth : public String {
    public:
        explicit SimpleAuth(uint8_t len, const char* value) : String(len, value, Type::SimpleAuth) {}
        explicit SimpleAuth(string value) : String(std::move(value), Type::SimpleAuth) {}
    };

    // This implementation is inexact, only support simple extensibleMatch
    class Filter : public Element {
    protected:
        string filterType;
        string matchValue;
    public:
        explicit Filter(uint8_t filterTypeLen, const char* filterType, uint8_t matchValueLen, const char* matchValue, Type type = Type::ExtensibleMatch) :
            Element(type),
            filterType(string(filterType, filterTypeLen)),
            matchValue(string(matchValue, matchValueLen)) {}
        explicit Filter(string filterType, string matchValue, Type type = Type::ExtensibleMatch) : Element(type), filterType(std::move(filterType)), matchValue(std::move(matchValue)) {}
        ostringstream& append(ostringstream& oss) final {
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
    class Attribute : public Element {
    protected:
        string value;
    public:
        explicit Attribute(uint8_t attributeLen, const char* attribute) :
                Element(Type::Attribute),
                value(string(attribute, attributeLen)) {}
        explicit Attribute(string value) : Element(Type::Attribute), value(value) {}
        ostringstream& append(ostringstream& oss) final {
            auto attribute = String(this->value);

            oss << (char)this->type;
            oss << (char)attribute.str().length();
            oss << attribute.str();
            return oss;
        }
    };
}

namespace LDAP {
    const uint8_t Header = 0x30;

    namespace Protocol {
        enum class Type : uint8_t {
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

        namespace SearchRequest {
            enum class Scope : uint8_t {
                BaseObject,
                SingleLevel,
                WholeSubtree
            };

            enum class DerefAliases : uint8_t {
                NeverDerefAliases,
                DerefInSearching,
                DerefFindingBaseObj,
                DerefAlways
            };
        }

        enum class FilterType {
            And = 0xa0,         // SET SIZE (1..MAX) OF filter Filter,
            Or,                 // SET SIZE (1..MAX) OF filter Filter,
            Not,                // Filter,
            EqualityMatch,      // AttributeValueAssertion,
            Substrings,         // SubstringFilter,
            GreaterOrEqual,     // AttributeValueAssertion,
            LessOrEqual,        // AttributeValueAssertion,
            Present,            // AttributeDescription,
            ApproxMatch,        // AttributeValueAssertion,
            ExtensibleMatch,    // MatchingRuleAssertion,
        };
    }

    class Op {
    private:
        Protocol::Type type;
        vector<BER::Element*> elements;
    public:
        explicit Op(Protocol::Type type) : type(type) {}
        Op& addElement(BER::Element* element) {
            elements.push_back(element);
            return *this;
        }
        string str() {
            ostringstream inside;
            for (auto element : this->elements) {
                element->append(inside);
            }
            ostringstream oss;
            oss << (char)this->type;
            oss << (char)inside.str().length();
            oss << inside.str();
            return oss.str();
        }
    };

    class Msg {
        uint8_t id;
        Op* op;
    public:
        Msg(uint8_t id, Op* op) : id(id), op(op) {}
        string str() {
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

    class MsgBuilder {
        static uint8_t id;
    public:
        MsgBuilder() = default;
        static unique_ptr<Msg> build(Op* op) { return std::unique_ptr<Msg>(new Msg(id++, op)); }
    };


    class BaseMsg {
    protected:
        Op op;
        unique_ptr<Msg> msg;
        explicit BaseMsg(Protocol::Type type) : op(Op(type)), msg(LDAP::MsgBuilder::build(&this->op)) {}
    public:
        string str() { return this->msg->str(); }
    };

    class BindRequest : public BaseMsg{
    public:
        BindRequest(string name, string passwd) : BaseMsg(Protocol::Type::BindRequest) {
            this->op.addElement(new BER::Integer<uint8_t>(0x03)) // Supported LDAP version
                    .addElement(new BER::String(std::move(name)))
                    .addElement(new BER::SimpleAuth(std::move(passwd)));
        }
    };

    class SearchRequest : public BaseMsg{
    public:
        SearchRequest(string baseObject,
                      string filterType,
                      string filterValue,
                      string attribute,
                      Protocol::SearchRequest::Scope scope = Protocol::SearchRequest::Scope::SingleLevel,
                      Protocol::SearchRequest::DerefAliases derefAliases = Protocol::SearchRequest::DerefAliases::NeverDerefAliases,
                      bool typesOnly = false) : BaseMsg(Protocol::Type::SearchRequest) {
            this->op.addElement(new BER::String(std::move(baseObject)))
                    .addElement(new BER::Enum<Protocol::SearchRequest::Scope>(scope))
                    .addElement(new BER::Enum<Protocol::SearchRequest::DerefAliases>(derefAliases))
                    .addElement(new BER::Integer<uint8_t>(0))
                    .addElement(new BER::Integer<uint8_t>(0))
                    .addElement(new BER::Bool(typesOnly))
                    .addElement(new BER::Filter(std::move(filterType), std::move(filterValue)))
                    .addElement(new BER::Attribute(std::move(attribute)));
        }
    };
}