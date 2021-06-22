// For more inspiration, see https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-ldap.c
// and http://luca.ntop.org/Teaching/Appunti/asn1.html
// and https://ldap.com/ldapv3-wire-protocol-reference-asn1-ber/

namespace LDAP
{
    #include "ber.hpp"
    using namespace BER;

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
        static unique_ptr<BER::UniversalElement<Boolean>> parse(string_view raw)
        {
            auto universal_element = unique_ptr<UniversalElement>(new UniversalElement(raw));
            auto element = static_unique_pointer_cast<BER::UniversalElement<Boolean>>(Element::parse(move(universal_element), raw));
//            auto element = static_pointer_cast<BER::UniversalElement<Boolean>>(Element::parse(move(universal_element), raw));
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
        static unique_ptr<BER::UniversalElement<Integer>> parse(string_view raw)
        {
            auto universal_element = unique_ptr<UniversalElement>(new UniversalElement(raw));
            auto element = static_unique_pointer_cast<BER::UniversalElement<Integer>>(Element::parse(move(universal_element), raw));
//            auto element = static_pointer_cast<BER::UniversalElement<Integer>>(Element::parse(move(universal_element), string_view(raw.data(), raw.size())));
            if (element == nullptr) {
                return nullptr;
            }
            element->compute_value();
            return element;
        }
        static unique_ptr<UniversalElement> parse_unchecked(string_view raw)
        {
            auto universal_element = unique_ptr<UniversalElement>(new UniversalElement(raw));
            auto element = static_unique_pointer_cast<BER::UniversalElement<Integer>>(Element::parse(move(universal_element), raw));
//            auto element = static_pointer_cast<BER::UniversalElement<Integer>>(Element::parse_unchecked(move(universal_element), string_view(raw.data(), raw.size())));
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
        static unique_ptr<BER::UniversalElement<OctetString>> parse(string_view raw)
        {
            auto universal_element = unique_ptr<UniversalElement>(new UniversalElement(raw));
            auto element = static_unique_pointer_cast<BER::UniversalElement<OctetString>>(Element::parse(move(universal_element), raw));
//            auto element = static_pointer_cast<BER::UniversalElement<OctetString>>(Element::parse(move(universal_element), raw));
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
        unique_ptr<T> make_shared_element(const char* data) {
            return unique_ptr<T>(T::parse(static_cast<const char *>((void*)data)));
        }

        bool compute_value() {
            auto data_size = this->length->get_data_size();

            size_t offset = 0;
            while(offset < data_size) {
                auto data = string_view(this->get_data_ptr<const char>(offset));
                auto header_tag = BER::HeaderTag::parse(data);

                // TODO: use a proper factory?
                unique_ptr<Element> downgraded_element = nullptr;
                switch(header_tag->number) {
                    #define BER_PARSE_TYPE(type) \
                        case type: { \
                            auto universal_element = UniversalElement<type>::parse(static_cast<const char *>((void*)data.data())); \
                            downgraded_element = static_unique_pointer_cast<BER::Element>(Element::parse(move(universal_element), data.data())); \
                        } break;
                    BER_PARSE_TYPE(Boolean)
                    BER_PARSE_TYPE(Integer)
                    BER_PARSE_TYPE(BitString)
                    BER_PARSE_TYPE(OctetString)
                    BER_PARSE_TYPE(Null)
                    BER_PARSE_TYPE(ObjectIdentifier)
                    BER_PARSE_TYPE(Sequence)
                    BER_PARSE_TYPE(Set)
                    BER_PARSE_TYPE(PrintableString)
                    BER_PARSE_TYPE(T61String)
                    BER_PARSE_TYPE(IA5String)
                    BER_PARSE_TYPE(UTCTime)
                    BER_PARSE_TYPE(ExtendedType)
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
        static unique_ptr<BER::UniversalElement<Sequence>> parse(string_view raw)
        {
            auto universal_element = unique_ptr<UniversalElement>(new UniversalElement(raw));
            auto element = static_unique_pointer_cast<BER::UniversalElement<Sequence>>(Element::parse(move(universal_element), raw));
            if (element == nullptr) return nullptr;
            bool success = element->compute_value();
            if (!success) {
                return nullptr;
            }
            return element;
        }
        constexpr vector<shared_ptr<Element>>* get_value_ptr() {
            return &this->value;
        }
        shared_ptr<Element> elem_at(size_t i) {
            if(i >= this->value.size()) return nullptr;
            return this->value[i];
        }
        template <typename T>
        shared_ptr<T> casted_elem_at(size_t i) {
            if(i >= this->value.size()) return nullptr;
            if (T::type != this->value[i]->tag->number) return nullptr;
            return static_pointer_cast<T>(this->value[i]);
        }
    };
    typedef UniversalElement<Integer> UniversalInteger;
}
