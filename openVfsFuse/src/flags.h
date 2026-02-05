#include <bitset>
#include <cstdint>
#include <iostream>

#include <map>

template <typename T>
class OFlags
{
public:
    OFlags(std::string name)
        : name(name) {

        };
    std::string name;
    std::map<T, std::string> names;
};

template <typename T>
class OFlag
{
public:
    OFlag(const OFlags<T> &type, uint64_t v)
        : type(type)
        , val(v)
    {
    }

    const OFlags<T> &type;
    T val;
};
#define ADD_O_FLAG(CLASS, KEY) CLASS.names[KEY] = #KEY;

template <typename T>
std::ostream &operator<<(std::ostream &out, OFlag<T> o)
{
    out << o.type.name << "(";
    constexpr auto size = sizeof(o.val) * 8;
    for (uint64_t p = 0; p < size; ++p) {
        const T key = (0x1 << p);
        if (o.val & key) {
            const auto it = o.type.names.find(key);
            if (it != o.type.names.end()) {
                out << it->second;
            } else {
                out << std::bitset<size>(key) << " 0x" << std::hex << key << std::dec;
            }
            out << "|";
        }
    }
    return out << ")";
}
