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

#include "string_view.hpp"
using namespace nonstd::literals;
using namespace nonstd;


using namespace std;

namespace BER
{
//    template <typename T>
//    struct ParseResult {
//        shared_ptr<T> value;
//        size_t length;
//    };

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

//    struct Header {
//        Type type;
//        size_t length;
//    };

    enum class MatchingRuleAssertion
    {
        MatchingRule = 0x81,
        Type,
        MatchValue,
        DnAttributes,
    };

    static const uint8_t HeaderTagMinSize = 1;
    static const uint8_t HeaderLengthMinSize = 1;

    static const uint8_t HeaderTypeNumberNBits   = 5;
    static const uint8_t HeaderTypeEncodingNBits = 1;
    static const uint8_t HeaderTypeClassNBits    = 2;

    static const uint8_t HeaderTypeTagShift      = 0;
    static const uint8_t HeaderTypeEncodingShift = HeaderTypeTagShift + HeaderTypeNumberNBits;
    static const uint8_t HeaderTypeClassShift    = HeaderTypeEncodingShift + HeaderTypeEncodingNBits;

    static const uint8_t HeaderTypeNumberLongShift = 7;
    static const uint8_t HeaderTypeNumberLongMask  = (1 << HeaderTypeNumberLongShift);

//    static const uint8_t HeaderTypeTagBits      = ((1 << HeaderTypeNumberNBits) - 1);
//    static const uint8_t HeaderTypeEncodingBits = ((1 << HeaderTypeEncodingNBits) - 1);
//    static const uint8_t HeaderTypeClassBits    = ((1 << HeaderTypeClassNBits) - 1);

//    static const uint8_t HeaderTypeTagMask      = (HeaderTypeTagBits << HeaderTypeTagShift);
//    static const uint8_t HeaderTypeEncodingMask = (HeaderTypeEncodingBits << HeaderTypeEncodingShift);
//    static const uint8_t HeaderTypeClassMask    = (HeaderTypeClassBits << HeaderTypeClassShift);


    enum HeaderTagNumber {
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

    enum HeaderTagType {
        Primitive,
        Constructed,
    };

    enum HeaderTagClass {
        Universal,
        Application,
        ContextSpecific,
        Private,
    };


    struct __attribute__ ((packed)) HeaderTag {
    public:
        HeaderTagNumber number: HeaderTypeNumberNBits;
        bool is_constructed: HeaderTypeEncodingNBits;
        HeaderTagClass asn1_class: HeaderTypeClassNBits;
    private:
        uint8_t* extra_tag_number;
    public:

        static constexpr HeaderTag* parse(const string_view raw) {
            return static_cast<BER::HeaderTag*>((void*)raw.data());
        }

        uint8_t get_size() const {
            uint8_t size = 0;
            // Check for high-tag-number form
            if(number == HeaderTagNumber::ExtendedType) {
                // Add 1 byte for every intermediate tag number
                while((uint8_t)this->get_data_ptr()[size] & HeaderTypeNumberLongMask) {
                    size += 1;
                }
                // Add final byte
                size += 1;
            }
            // Minimal size of the tag
            size += 1;
            return size;
        }

        constexpr char* buf_extra_tag_number() const {
            return static_cast<char*>((void*)&this->extra_tag_number);
        }

        template<typename T = uint8_t>
        constexpr T* get_data_ptr() const {
            return static_cast<T*>((void*)&this->extra_tag_number);
        }

        inline string_view get_string_view() const {
            return string_view(static_cast<const char *>((void*)this));
        }
    };

    struct UsableDataSize {
        size_t data_size;
        bool is_usable;
    };
    struct __attribute__ ((packed)) HeaderLength {
        uint8_t length: 7;
        uint8_t is_long: 1;
    private:
        uint8_t* extra_length;
    public:

        static constexpr HeaderLength* parse(const string_view raw) {
            return static_cast<BER::HeaderLength*>((void*)raw.data());
        }

        uint8_t length_at(const uint8_t offset) {
            if(offset > length) {
                return 0;
            }
            return (uint8_t) this->get_data_ptr()[offset];
        }

        constexpr uint8_t get_size() const {
            return (!this->is_long) ? 1 : 1 + this->length;
        }

        template<typename T = uint8_t>
        constexpr T* get_data_ptr() const {
            return static_cast<T*>((void*)&this->extra_length);
        }

        constexpr string_view get_string_view() const {
            return string_view(static_cast<const char *>((void*)this));
        }

        bool is_data_size_usable() const {
            // Directly return true for short form
            if (!this->is_long) return true;

            // Check if the long-form size can be stored in size_t, because we are cowards
            // If there is more bytes of length than what we can store in a size_t, check if there are empty
            if(this->length > sizeof(size_t)) {
                for(int i = 0; i < this->length - sizeof(size_t); i++) {
                    if (this->extra_length[this->length-i-1] > 0)
                        return false;
                }
            }
            return true;
        }

        size_t get_data_size() const {
            // Directly return the size for short form
            if (!this->is_long)
                return this->length;

            // Compute the size only on the last bytes
            size_t usable_size = 0;
            for(uint8_t i = this->length - sizeof(size_t); i < this->length; i++) {
                usable_size += this->extra_length[i];
            }
            return usable_size;
        }
    };

    struct Element {
        const string_view data;

        HeaderTag* tag = nullptr;
        HeaderLength* length = nullptr;
        string_view extra_data = {};

//        virtual ~Element() {};

    public:
        explicit Element(const string_view raw) : data(raw) {}

    protected:
        static shared_ptr<Element> parse_unchecked(shared_ptr<Element> element, const string_view raw) {
            element->tag = HeaderTag::parse(raw);
            element->length = HeaderLength::parse(&element->tag->get_string_view().data()[element->tag->get_size()]);
            // Do not point to invalid data if the packet is not supposed to contain any
            if (element->length->length > 0)
                element->extra_data = &element->length->get_string_view().data()[element->length->get_size()];
            return element;
        }

        static shared_ptr<Element> parse(shared_ptr<Element> element, const string_view raw) {
            // Allocate a new Element
            auto cur_offset = 0;
            size_t data_size = 0;

            // Parse the tag
            element->tag = HeaderTag::parse(raw);
            // Add the length of the tag to the parsed data offset
            cur_offset += element->tag->get_size();
            // Check if the raw data can fit the full tag and the minimum header length size
            if (raw.size() < cur_offset + HeaderLengthMinSize) goto cleanup;

            // Parse the length
            element->length = HeaderLength::parse(&element->tag->get_string_view().data()[element->tag->get_size()]);
            // Add the length of the tag to the parsed data offset
            cur_offset += element->length->get_size();
            // Check if the raw data can fit the whole header length size
            if (raw.size() < cur_offset) goto cleanup;
            // Check if we can fit the data length into a size_t to work on it after, because we are cowards and don't like BigInt
            if (!element->length->is_data_size_usable()) goto cleanup;
            // Get the data size
            data_size = element->length->get_data_size();
            if (data_size == 0) return element;
            // Check if we can fit the data in the raw data, omit parsed data here to avoid overflow
            if (raw.size() < data_size) goto cleanup;

            // Save pointer to extra data if any
            element->extra_data = &element->length->get_string_view().data()[element->length->get_size()];

            return element;

            cleanup:
            return nullptr;
        }

    public:
        static shared_ptr<Element> parse_unchecked(const string_view raw) {
            auto element = shared_ptr<Element>(new Element(raw));
            return parse_unchecked(move(element), raw);
        }

        static shared_ptr<Element> parse(const string_view raw) {
            auto element = shared_ptr<Element>(new Element(raw));
            return parse(move(element), raw);
        }

        template<typename T>
        constexpr T* get_data_ptr(const size_t offset = 0) const {
            return static_cast<T*>((void *) &this->extra_data.data()[offset]);
        }
        const size_t get_size() const {
            return this->tag->get_size() + this->length->get_size() + this->length->get_data_size();
        }

        template<typename T>
        shared_ptr<T> try_as() {
            return static_pointer_cast<T>(shared_ptr<Element>(this));
        }
    };

    // UniversalElement
    template<HeaderTagNumber T> struct UniversalElement : Element {
    public:
        static constexpr HeaderTagNumber type = T;
    };

    template<> struct UniversalElement<Null> : Element {
    public:
        static constexpr HeaderTagNumber type = Null;
    };
    typedef UniversalElement<Null> UniversalNull;

    template<> struct UniversalElement<Boolean> : Element {
    public:
        static constexpr HeaderTagNumber type = Boolean;
    private:
        bool value = false;
    public:
        explicit UniversalElement(const string_view raw) : Element(raw) {}
    private:
        void compute_value() {
            auto data_size = this->length->get_data_size();
            if (data_size > sizeof(this->value)) return;
            this->value = !!*this->get_data_ptr<uint8_t>();
        }

    public:
        static shared_ptr<BER::UniversalElement<Boolean>> parse(string_view raw)
        {
            auto universal_element = shared_ptr<UniversalElement>(new UniversalElement(raw));
            auto element = static_pointer_cast<BER::UniversalElement<Boolean>>(Element::parse(move(universal_element), raw));
            if (element == nullptr) return nullptr;
            element->compute_value();
            return element;
        }
        constexpr const bool get_value() const {
            return value;
        }
    };
    typedef UniversalElement<Boolean> UniversalBoolean;

    template<> struct UniversalElement<Integer> : Element {
    public:
        static constexpr HeaderTagNumber type = Integer;
    private:
        int32_t value = 0;
    public:
        explicit UniversalElement(const string_view raw) : Element(raw) {}
    private:
        void compute_value() {
            const auto data_size = this->length->get_data_size();
            if (data_size > sizeof(this->value)) return;

            const int8_t first_byte = *this->get_data_ptr<int8_t>();
            // We are dealing with a positive number
            if(first_byte >= 0) {
                for (size_t i = 0; i < data_size; i++) {
                    this->value += this->get_data_ptr<uint8_t>()[i] << (8 * (data_size - i - 1));
                }
                return;
            }
            // We are dealing with a negative number
            uint32_t unsigned_value = 0;
            for(size_t i = 0; i < data_size; i++) {
                unsigned_value += this->get_data_ptr<uint8_t>()[i] << (8*(sizeof(this->value)-i-1));
            }
            this->value = ((int32_t)unsigned_value >> (8 * (sizeof(this->value) - data_size)));
        }
    public:
        static shared_ptr<BER::UniversalElement<Integer>> parse(string_view raw)
        {
            auto universal_element = shared_ptr<UniversalElement>(new UniversalElement(raw));
            auto element = static_pointer_cast<BER::UniversalElement<Integer>>(Element::parse(move(universal_element), string_view(raw.data(), raw.size())));
            if (element == nullptr) {
                return nullptr;
            }
            element->compute_value();
            return element;
        }
        static shared_ptr<UniversalElement> parse_unchecked(string_view raw)
        {
            auto universal_element = shared_ptr<UniversalElement>(new UniversalElement(raw));
            auto element = static_pointer_cast<BER::UniversalElement<Integer>>(Element::parse_unchecked(move(universal_element), string_view(raw.data(), raw.size())));
            if (element == nullptr) return nullptr;
            element->compute_value();
            return element;
        }
        constexpr const int32_t get_value() const {
            return value;
        }
    };
    typedef UniversalElement<Integer> UniversalInteger;


    // TODO: support constructed strings
    template<> struct UniversalElement<OctetString> : Element {
    protected:
        static constexpr HeaderTagNumber type = OctetString;
    public:
        explicit UniversalElement(const string_view raw) : Element(raw) {}
        static shared_ptr<BER::UniversalElement<OctetString>> parse(string_view raw)
        {
            auto universal_element = shared_ptr<UniversalElement>(new UniversalElement(raw));
            auto element = static_pointer_cast<BER::UniversalElement<OctetString>>(Element::parse(move(universal_element), raw));
            if (element == nullptr) return nullptr;
            return element;
        }
        constexpr const string_view get_value() const {
            return extra_data;
        }
    };
    template<> struct UniversalElement<IA5String> : UniversalElement<OctetString> {
    public:
        static constexpr HeaderTagNumber type = IA5String;
    };
    template<> struct UniversalElement<PrintableString> : UniversalElement<OctetString> {
    public:
        static constexpr HeaderTagNumber type = PrintableString;
    };
    template<> struct UniversalElement<T61String> : UniversalElement<OctetString> {
    public:
        static constexpr HeaderTagNumber type = T61String;
    };
    typedef UniversalElement<OctetString> UniversalOctetString;
    typedef UniversalElement<IA5String> UniversalIA5String;
    typedef UniversalElement<PrintableString> UniversalPrintableString;
    typedef UniversalElement<T61String> UniversalT61String;

    template<> struct UniversalElement<Sequence> : Element {
    public:
        static constexpr HeaderTagNumber type = Sequence;
    private:
        vector<shared_ptr<Element>> value;

    public:
        explicit UniversalElement(const string_view raw) : Element(raw) {}

    private:
        template <HeaderTagNumber N, typename T=UniversalElement<N>>
        shared_ptr<T> make_shared_element(const char* data) {
            return shared_ptr<T>(T::parse(static_cast<const char *>((void*)data)));
        }

        bool compute_value() {
            auto data_size = this->length->get_data_size();

            size_t offset = 0;
            while(offset < data_size) {
                auto data = string_view(this->get_data_ptr<const char>(offset));
                auto header_tag = BER::HeaderTag::parse(data);

                shared_ptr<Element> downgraded_element = nullptr;
                switch(header_tag->number) {
                    case Boolean: {
                        auto universal_element = UniversalElement<Boolean>::parse(static_cast<const char *>((void*)data.data()));
                        downgraded_element = static_pointer_cast<Element>(universal_element);
                    } break;

                    case Integer: {
                        auto universal_element = UniversalElement<Integer>::parse(static_cast<const char *>((void*)data.data()));
                        downgraded_element = static_pointer_cast<Element>(universal_element);
                    } break;

                    case BitString:
                        break;
                    case OctetString:
                        break;
                    case Null:
                        break;
                    case ObjectIdentifier:
                        break;
                    case Sequence:
                        break;
                    case Set:
                        break;
                    case PrintableString:
                        break;
                    case T61String:
                        break;
                    case IA5String:
                        break;
                    case UTCTime:
                        break;
                    case ExtendedType:
                        break;
                }
                if (downgraded_element == nullptr) {
                    for(auto& cur_element: this->value) {
                        cur_element.reset();
                    }
                    return false;
                }

                offset += downgraded_element->get_size();
                this->value.push_back(move(downgraded_element));
            }
            return true;
        }
    public:
        static shared_ptr<BER::UniversalElement<Sequence>> parse(string_view raw)
        {
            auto universal_element = shared_ptr<UniversalElement>(new UniversalElement(raw));
            auto element = static_pointer_cast<BER::UniversalElement<Sequence>>(Element::parse(universal_element, raw));
            if (element == nullptr) return nullptr;
            bool success = universal_element->compute_value();
            if (!success) {
                return nullptr;
            }
            return universal_element;
        }
        constexpr const vector<shared_ptr<Element>>& get_value() const {
            return value;
        }
    };
    typedef UniversalElement<Integer> UniversalInteger;
}
