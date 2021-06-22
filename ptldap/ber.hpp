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

namespace BER
{
    #include "string_view.hpp"

    using namespace nonstd::literals;
    using namespace nonstd;


    using namespace std;

    /// conversion: unique_ptr<FROM>->FROM*->TO*->unique_ptr<TO>
    template<typename TO, typename FROM>
    static unique_ptr<TO> static_unique_pointer_cast (unique_ptr<FROM>&& old){
        return unique_ptr<TO>{static_cast<TO*>(old.release())};
    }


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
        uint8_t extra_tag_number[];
    public:

        static constexpr HeaderTag* parse(const string_view raw) {
            return static_cast<BER::HeaderTag*>((void*)raw.data());
        }

        // TODO: check for bound for extended type?
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

    struct __attribute__ ((packed)) HeaderLength {
        uint8_t length: 7;
        uint8_t is_long: 1;
        uint8_t extra_length[];
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
                usable_size += this->extra_length[i] << (8 * i);
            }
            return usable_size;
        }
    };

    enum ParseType {
        None,
        Unchecked,
        Checked,
    };

    enum ElemStateType {
        Empty,
        ParsedInvalid,
        ParsedMaybeInvalid,
        Valid,
    };

    struct Element {
        string_view data;

        HeaderTag* tag = nullptr;
        HeaderLength* length = nullptr;
        string_view extra_data = {};

        unique_ptr<string> storage = nullptr;

        ElemStateType state = ElemStateType::Empty;

    public:
        // Parse element
        explicit Element(const string_view raw, ParseType parse = ParseType::Unchecked) : data(raw) {
            switch (parse) {
                case ParseType::Unchecked:
                    this->internal_parse_unchecked();
                    break;
                case ParseType::Checked:
                    this->internal_parse();
                    break;
                default:
                    break;
            }
        }

        // Simple element build
        explicit Element(HeaderTagNumber number, HeaderTagClass asn1_class, size_t length, bool is_constructed = false) {
            size_t element_size = HeaderTagMinSize + HeaderLengthMinSize + length;
            size_t length_size = 0;
            if(length > (1 << HeaderTypeNumberLongShift) - 1) {
                length_size = log2(length) / 8;
                element_size += length_size;
            }
            this->storage = make_unique<string>(element_size, '\0');
            this->data = *this->storage;

            size_t offset = 0;
            this->tag = (HeaderTag *) &this->data[offset];
            this->tag->number = number;
            this->tag->is_constructed = is_constructed;
            this->tag->asn1_class = asn1_class;

            offset += HeaderTagMinSize;
            this->length = (HeaderLength *) &this->data[offset];
            if (length > (1 << HeaderTypeNumberLongShift) - 1) {
                this->length->is_long = true;
                this->length->length = length_size;
                for(size_t i = length_size - 1; i < length_size; i++) {
                    ((uint8_t*)&this->length->extra_length)[i] = (length_size >> (8*(length_size-i-1))) & 0xff;
                }
                offset += length_size;
            } else {
                this->length->length = length;
                offset += HeaderLengthMinSize;
            }

            this->extra_data = &this->data[offset];
        }

    protected:
        Element* internal_parse_unchecked() {
            this->tag = HeaderTag::parse(this->data);
            auto tag_size = this->tag->get_size();
            this->length = HeaderLength::parse(&this->tag->get_string_view().data()[tag_size]);
            auto length_size = this->length->get_size();
            // Do not point to invalid data if the packet is not supposed to contain any
            if (this->length->length > 0)
                this->extra_data = &this->length->get_string_view().data()[length_size];
            this->state = ElemStateType::ParsedMaybeInvalid;
            return this;
        }

        Element* internal_parse() {
            auto cur_offset = 0;
            size_t data_size = 0;

            // Parse the tag
            this->tag = HeaderTag::parse(this->data);
            // Add the length of the tag to the parsed data offset
            cur_offset += this->tag->get_size();
            // Check if the raw data can fit the full tag and the minimum header length size
            if (this->data.size() < cur_offset + HeaderLengthMinSize) goto cleanup;

            // Parse the length
            this->length = HeaderLength::parse(&this->tag->get_string_view().data()[this->tag->get_size()]);
            // Add the length of the tag to the parsed data offset
            cur_offset += this->length->get_size();
            // Check if the raw data can fit the whole header length size
            if (this->data.size() < cur_offset) goto cleanup;
            // Check if we can fit the data length into a size_t to work on it after, because we are cowards and don't like BigInt
            if (!this->length->is_data_size_usable()) goto cleanup;
            // Get the data size
            data_size = this->length->get_data_size();
            if (data_size == 0) return this;
            // Check if we can fit the data in the raw data, omit parsed data here to avoid overflow
            if (this->data.size() < data_size) goto cleanup;

            // Save pointer to extra data if any
            this->extra_data = &this->length->get_string_view().data()[this->length->get_size()];

            this->state = ElemStateType::Valid;

            return this;

            cleanup:
            this->state = ElemStateType::ParsedInvalid;
            return nullptr;
        }

        ElemStateType check_state() {
            if(this->tag == nullptr) return ElemStateType::Empty;
            if(this->length == nullptr) return ElemStateType::Empty;

            size_t cur_offset = 0;
            auto data_size = this->data.size();
            auto tag_size = this->tag->get_size();
            auto length_size = this->tag->get_size();

            // Add the length of the tag to the parsed data offset
            cur_offset += tag_size;
            // Check if the raw data can fit the full tag and the minimum header length size
            if (this->data.size() < cur_offset + HeaderLengthMinSize) return ElemStateType::ParsedInvalid;

            // Add the length of the tag to the parsed data offset
            cur_offset += this->length->get_size();
            // Check if the raw data can fit the whole header length size
            if (this->data.size() < cur_offset) return ElemStateType::ParsedInvalid;
            // Check if we can fit the data length into a size_t to work on it after, because we are cowards and don't like BigInt
            if (!this->length->is_data_size_usable()) return ElemStateType::ParsedInvalid;
            // Get the data size
            size_t extra_data_size = this->length->get_data_size();
            if (extra_data_size == 0) return ElemStateType::Valid;
            cur_offset += extra_data_size;
            // Check if we can fit the data in the raw data, omit parsed data here to avoid overflow
            if (this->data.size() < cur_offset) return ElemStateType::ParsedInvalid;

            return ElemStateType::Valid;
        }

    public:
        static unique_ptr<Element> parse_unchecked(const string_view raw) {
            return unique_ptr<Element>(new Element(raw, ParseType::Unchecked));
        }

        static unique_ptr<Element> parse(const string_view raw) {
            // Manually parse so we can handle errors and return a nullptr instead
            auto element = new Element(raw, ParseType::None);
            return unique_ptr<Element>(element->internal_parse());
        }

        template<typename T>
        constexpr T* get_data_ptr(const size_t offset = 0) const {
            return static_cast<T*>((void *) &this->extra_data.data()[offset]);
        }

        const size_t get_size() const {
            return this->tag->get_size() + this->length->get_size() + this->length->get_data_size();
        }

        template<typename T>
        unique_ptr<T> try_as() {
            return static_pointer_cast<T>(unique_ptr<Element>(this));
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
        explicit UniversalElement(const string_view raw) : Element(raw, ParseType::Checked) {
            auto data_size = this->length->get_data_size();
            if (data_size > 0) goto set_as_invalid;
            this->state = Valid;
            return;

            set_as_invalid:
            this->state = ParsedInvalid;
        }

        explicit UniversalElement() : Element(HeaderTagNumber::Null, HeaderTagClass::Universal, 1) {
            this->state = Valid;
        }
    };
    typedef UniversalElement<Null> UniversalNull;

    template<> struct UniversalElement<Boolean> : Element {
    public:
        static constexpr HeaderTagNumber type = Boolean;
    private:
        bool value = false;
    public:
        explicit UniversalElement(const string_view raw) : Element(raw, ParseType::Checked) {
            auto data_size = this->length->get_data_size();
            if (data_size > sizeof(this->value)) goto set_as_invalid;
            this->value = !!*this->get_data_ptr<uint8_t>();
            this->state = Valid;
            return;

            set_as_invalid:
            this->state = ParsedInvalid;
        }

        explicit UniversalElement(const bool value) : Element(HeaderTagNumber::Boolean, HeaderTagClass::Universal, 1) {
            *this->get_data_ptr<uint8_t>() = (uint8_t) !!value;
            this->value = value;
            this->state = Valid;
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
        bool compute_value() {
            const auto data_size = this->length->get_data_size();
            if (data_size > sizeof(this->value)) return false;

            const int8_t first_byte = *this->get_data_ptr<int8_t>();
            // We are dealing with a positive number
            if(first_byte >= 0) {
                for (size_t i = 0; i < data_size; i++) {
                    this->value += this->get_data_ptr<uint8_t>()[i] << (8 * (data_size - i - 1));
                }
            }
            // We are dealing with a negative number
            else {
                uint32_t unsigned_value = 0;
                for(size_t i = 0; i < data_size; i++) {
                    unsigned_value += this->get_data_ptr<uint8_t>()[i] << (8*(sizeof(this->value)-i-1));
                }
                this->value = ((int32_t)unsigned_value >> (8 * (sizeof(this->value) - data_size)));
            }

            return true;
        }
        constexpr uint8_t get_length_from_value(int32_t value) {
           return (
                   (value < -(1<<23) | value >= (1<<23)) ? 4 :
                   (value < -(1<<15) | value >= (1<<15)) ? 3 :
                   (value < -(1<< 7) | value >= (1<< 7)) ? 2 :
                                                           1
           );
        }

    public:
        explicit UniversalElement(const string_view raw) : Element(raw) {
           if(this->compute_value()) {
              this->state = Valid;
              return;
           }

           set_as_invalid:
           this->state = ParsedInvalid;
        }

        explicit UniversalElement(const int32_t value) : Element(HeaderTagNumber::Integer, HeaderTagClass::Universal, get_length_from_value(value)) {
            if (value >= 0) {
                auto data_ptr = this->get_data_ptr<uint8_t>();
                for (uint8_t i = 0; i < this->length->length; i++) {
                    data_ptr[this->length->length - i -1] = (value >> (8*i)) & 0xff;
                }
            } else {
                auto data_ptr = this->get_data_ptr<uint8_t>();
                const auto n_bytes = this->length->length;
                for(int i = 0; i < n_bytes; i++) {
                    data_ptr[i] = (value >> (8*(n_bytes-i-1))) & 0xff;
                }
            }
            this->value = value;
            this->state = Valid;
        }

        constexpr const int32_t get_value() const {
            return value;
        }
    };
    typedef UniversalElement<Integer> UniversalInteger;


    // TODO: support constructed strings
//    template<> struct UniversalElement<OctetString> : Element {
//    protected:
//        static constexpr HeaderTagNumber type = OctetString;
//    public:
//        explicit UniversalElement(const string_view raw) : Element(raw, ParseType::Checked) {
//           auto data_size = this->length->get_data_size();
//           if (data_size > sizeof(this->value)) goto set_as_invalid;
//           this->value = !!*this->get_data_ptr<uint8_t>();
//           this->state = Valid;
//           return;
//
//           set_as_invalid:
//           this->state = ParsedInvalid;
//        }
//
//        explicit UniversalElement(const string value) : Element(HeaderTagNumber::Boolean, HeaderTagClass::Universal, 1) {
//           *this->get_data_ptr<uint8_t>() = (uint8_t) !!value;
//           this->value = value;
//           this->state = Valid;
//        }
//
//        constexpr const bool get_value() const {
//           return value;
//        }



//        explicit UniversalElement(const string_view raw) : Element(raw) {}
//        static unique_ptr<BER::UniversalElement<OctetString>> parse(string_view raw)
//        {
//            auto universal_element = unique_ptr<UniversalElement>(new UniversalElement(raw));
//            auto element = static_unique_pointer_cast<BER::UniversalElement<OctetString>>(Element::parse(move(universal_element), raw));
////            auto element = static_pointer_cast<BER::UniversalElement<OctetString>>(Element::parse(move(universal_element), raw));
//            if (element == nullptr) return nullptr;
//            return element;
//        }
//        constexpr const string_view get_value() const {
//            return extra_data;
//        }
//    };
//    template<> struct UniversalElement<IA5String> : UniversalElement<OctetString> {
//    public:
//        static constexpr HeaderTagNumber type = IA5String;
//    };
//    template<> struct UniversalElement<PrintableString> : UniversalElement<OctetString> {
//    public:
//        static constexpr HeaderTagNumber type = PrintableString;
//    };
//    template<> struct UniversalElement<T61String> : UniversalElement<OctetString> {
//    public:
//        static constexpr HeaderTagNumber type = T61String;
//    };
//    typedef UniversalElement<OctetString> UniversalOctetString;
//    typedef UniversalElement<IA5String> UniversalIA5String;
//    typedef UniversalElement<PrintableString> UniversalPrintableString;
//    typedef UniversalElement<T61String> UniversalT61String;

//    template<> struct UniversalElement<Sequence> : Element {
//    public:
//        static constexpr HeaderTagNumber type = Sequence;
//    private:
//        vector<shared_ptr<Element>> value;
//
//    public:
//        explicit UniversalElement(const string_view raw) : Element(raw) {}
//
//    private:
//        template <HeaderTagNumber N, typename T=UniversalElement<N>>
//        unique_ptr<T> make_shared_element(const char* data) {
//            return unique_ptr<T>(T::parse(static_cast<const char *>((void*)data)));
//        }
//
//        bool compute_value() {
//            auto data_size = this->length->get_data_size();
//
//            size_t offset = 0;
//            while(offset < data_size) {
//                auto data = string_view(this->get_data_ptr<const char>(offset));
//                auto header_tag = BER::HeaderTag::parse(data);
//
//                // TODO: use a proper factory?
//                unique_ptr<Element> downgraded_element = nullptr;
//                switch(header_tag->number) {
//                    #define BER_PARSE_TYPE(type) \
//                        case type: { \
//                            auto universal_element = UniversalElement<type>::parse(static_cast<const char *>((void*)data.data())); \
//                            downgraded_element = static_unique_pointer_cast<BER::Element>(Element::parse(move(universal_element), data.data())); \
//                        } break;
//                    BER_PARSE_TYPE(Boolean)
//                    BER_PARSE_TYPE(Integer)
//                    BER_PARSE_TYPE(BitString)
//                    BER_PARSE_TYPE(OctetString)
//                    BER_PARSE_TYPE(Null)
//                    BER_PARSE_TYPE(ObjectIdentifier)
//                    BER_PARSE_TYPE(Sequence)
//                    BER_PARSE_TYPE(Set)
//                    BER_PARSE_TYPE(PrintableString)
//                    BER_PARSE_TYPE(T61String)
//                    BER_PARSE_TYPE(IA5String)
//                    BER_PARSE_TYPE(UTCTime)
//                    BER_PARSE_TYPE(ExtendedType)
//                }
//                if (downgraded_element == nullptr) {
//                    for(auto& cur_element: this->value) {
//                        cur_element.reset();
//                    }
//                    return false;
//                }
//
//                offset += downgraded_element->get_size();
//                this->value.push_back(move(downgraded_element));
//            }
//            return true;
//        }
//    public:
//        static unique_ptr<BER::UniversalElement<Sequence>> parse(string_view raw)
//        {
//            auto universal_element = unique_ptr<UniversalElement>(new UniversalElement(raw));
//            auto element = static_unique_pointer_cast<BER::UniversalElement<Sequence>>(Element::parse(move(universal_element), raw));
//            if (element == nullptr) return nullptr;
//            bool success = element->compute_value();
//            if (!success) {
//                return nullptr;
//            }
//            return element;
//        }
//        constexpr vector<shared_ptr<Element>>* get_value_ptr() {
//            return &this->value;
//        }
//        shared_ptr<Element> elem_at(size_t i) {
//            if(i >= this->value.size()) return nullptr;
//            return this->value[i];
//        }
//        template <typename T>
//        shared_ptr<T> casted_elem_at(size_t i) {
//            if(i >= this->value.size()) return nullptr;
//            if (T::type != this->value[i]->tag->number) return nullptr;
//            return static_pointer_cast<T>(this->value[i]);
//        }
//    };
//    typedef UniversalElement<Integer> UniversalInteger;
}
