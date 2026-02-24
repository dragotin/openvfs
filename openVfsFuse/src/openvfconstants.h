// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hannah von Reth <h.vonreth@opencloud.eu>

#pragma once
#include <assert.h>
#include <cstdint>
#include <string_view>

/**
 * Define the available attributes and their filed names in the JSON object
 */
namespace OpenVfsConstants {

constexpr uint8_t Version = 1;

namespace XAttributeNames {
    /**
     * the XAttribute name for OpenVfs objects.
     */
    constexpr std::string_view Data = "user.openvfs.data";
    /**
     * Xattribute provided by OpenVFSFuse to determine the size on the filesystem.
     */
    constexpr std::string_view RealSize = "user.openvfs.realize";
    constexpr std::string_view Owner = "user.openvfs.owner";
    constexpr std::string_view Version = "user.openvfs.version";
}

enum class Attributes : uint8_t { Etag, FileId, Size, State, PinState };

enum class States : uint8_t { Hydrated, DeHydrated, Hydrating };

enum class PinStates : uint8_t { Unspecified, OnlineOnly, AlwaysLocal, Inherited, Excluded };

constexpr std::string_view name(Attributes name)
{
    switch (name) {
    case Attributes::Etag:
        return "etag";
    case Attributes::FileId:
        return "fileid";
    case Attributes::Size:
        return "size";
    case Attributes::State:
        return "state";
    case Attributes::PinState:
        return "pinstate";
    }
    assert(false);
    return "";
}

constexpr std::string_view name(States name)
{
    switch (name) {
    case States::Hydrated:
        return "hydrated";
    case States::DeHydrated:
        return "dehydrated";
    case States::Hydrating:
        return "hydrating";
    }
    assert(false);
    return "";
}

constexpr std::string_view name(PinStates name)
{
    switch (name) {
    case PinStates::OnlineOnly:
        return "hydrated";
    case PinStates::AlwaysLocal:
        return "dehydrated";
    case PinStates::Inherited:
        return "inherited";
    case PinStates::Excluded:
        return "excluded";
    case PinStates::Unspecified:
        return "unspecified";
    }
    assert(false);
    return "";
}


}
