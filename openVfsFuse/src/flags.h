// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Hannah von Reth <h.vonreth@opencloud.eu>
#pragma once

#include <concepts>
#include <format>
#include <limits>
#include <ostream>
#include <sstream>
#include <string>
#include <type_traits>

// Traits: one specialization per concrete flag class (not per integer type).
template <typename Flag>
struct OFlagTraits;

// CRTP base so member functions (like to_string()) can talk about the *real* flag type,
// not just the underlying integer type.
template <typename Derived, typename T>
class OFlag
{
public:
    using derived_type = Derived;
    using value_type = T;

    constexpr explicit OFlag(T v)
        : val(v)
    {
    }

    T val{};

    [[nodiscard]] std::string to_string() const
    {
        std::ostringstream s;

        // If the derived type has an operator<<, use it. Otherwise fall back to the raw value.
        // This avoids hard errors for plain OFlag<...> while still giving rich output for flag classes.
        if constexpr (requires { s << static_cast<const Derived &>(*this); }) {
            s << static_cast<const Derived &>(*this);
        } else {
            s << val;
        }

        return s.str();
    }
};

#define O_FLAG_BEGIN(CLASS, TYPE)                                                                                                                              \
    class CLASS : public OFlag<CLASS, TYPE>                                                                                                                    \
    {                                                                                                                                                          \
    public:                                                                                                                                                    \
        using OFlag<CLASS, TYPE>::OFlag;                                                                                                                       \
    };                                                                                                                                                         \
    template <>                                                                                                                                                \
    struct OFlagTraits<CLASS>                                                                                                                                  \
    {                                                                                                                                                          \
        using Flag = CLASS;                                                                                                                                    \
        using value_type = TYPE;                                                                                                                               \
        static constexpr const char *class_name()                                                                                                              \
        {                                                                                                                                                      \
            return #CLASS;                                                                                                                                     \
        }                                                                                                                                                      \
        static std::string flag_to_string(value_type v)                                                                                                        \
        {                                                                                                                                                      \
            switch (v) {
#define O_FLAG_END                                                                                                                                             \
    default:                                                                                                                                                   \
        return std::format("b{:b} 0{:o} 0x{:x}", v, v, v);                                                                                                     \
        }                                                                                                                                                      \
        }                                                                                                                                                      \
        }                                                                                                                                                      \
        ;

#define O_FLAG_ADD(KEY)                                                                                                                                        \
    case KEY:                                                                                                                                                  \
        return #KEY;
#define O_FLAG_ADD_NAMED(KEY, NAME)                                                                                                                            \
    case KEY:                                                                                                                                                  \
        return NAME;

template <typename Flag>
concept FlagPrintable = requires
{
    typename std::remove_cvref_t<Flag>::value_type;
    typename OFlagTraits<std::remove_cvref_t<Flag>>::value_type;
}
&&std::derived_from<std::remove_cvref_t<Flag>, OFlag<std::remove_cvref_t<Flag>, typename std::remove_cvref_t<Flag>::value_type>> &&requires(
    typename std::remove_cvref_t<Flag>::value_type v)
{
    {OFlagTraits<std::remove_cvref_t<Flag>>::class_name()}->std::convertible_to<const char *>;
    {OFlagTraits<std::remove_cvref_t<Flag>>::flag_to_string(v)}->std::convertible_to<std::string>;
};

// Stream output ONLY for actual flag classes produced by O_FLAG_BEGIN/END (i.e., with traits).
template <FlagPrintable Flag>
std::ostream &operator<<(std::ostream &out, const Flag &o)
{
    using CleanFlag = std::remove_cvref_t<Flag>;
    using Traits = OFlagTraits<CleanFlag>;
    using T = typename Traits::value_type;
    using U = std::make_unsigned_t<T>;

    out << Traits::class_name() << "(";

    if (o.val == static_cast<T>(0)) {
        out << Traits::flag_to_string(static_cast<T>(0));
        return out << ")";
    }

    constexpr auto bits = std::numeric_limits<U>::digits;
    bool first = true;

    for (unsigned p = 0; p < bits; ++p) {
        const U mask = (U{1} << p);
        if ((static_cast<U>(o.val) & mask) != 0) {
            if (!first) {
                out << "|";
            }
            first = false;
            out << Traits::flag_to_string(static_cast<T>(mask));
        }
    }

    return out << ")";
}
