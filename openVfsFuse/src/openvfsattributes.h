// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hannah von Reth <h.vonreth@opencloud.eu>
#pragma once
#include "openvfconstants.h"

#include "nlohmann/json.hpp"

/**
 * Header only implementation of a simple parser for PlaceHolderAttributes JSON objects.
 */
namespace OpenVfsAttributes {
class PlaceHolderAttributes
{
public:

    std::filesystem::path absolutePath;
    std::string etag;
    std::string fileId;
    std::size_t size = 0;
    // assume an exisitng file by default
    OpenVfsConstants::States state = OpenVfsConstants::States::Hydrated;
    OpenVfsConstants::PinStates pinState = OpenVfsConstants::PinStates::Inherited;

    bool isOk() const { return _ok; }

    operator bool() const { return isOk(); }

    std::vector<uint8_t> toData() const
    {
        using namespace OpenVfsConstants;
        assert(*this);
        return nlohmann::json::to_msgpack({{name(Attributes::Etag), etag}, {name(Attributes::FileId), fileId}, {name(Attributes::Size), size},
            {name(Attributes::State), state}, {name(Attributes::PinState), pinState}});
    }

    static PlaceHolderAttributes create(const std::filesystem::path &absolutePath, const std::string &etag, const std::string &fileId, std::size_t size)
    {
        using namespace OpenVfsConstants;
        return {absolutePath, etag, fileId, size, States::DeHydrated, PinStates::Inherited};
    }

    static PlaceHolderAttributes fromData(const std::filesystem::path &absolutePath, const std::vector<uint8_t> &d)
    {
        using namespace OpenVfsConstants;
        if (d.empty()) {
            return {absolutePath};
        }
        const auto j = nlohmann::json::from_msgpack(d);
        return {absolutePath, j.at(name(Attributes::Etag)), j.at(name(Attributes::FileId)), j.at(name(Attributes::Size)), j.at(name(Attributes::State)),
            j.at(name(Attributes::PinState))};
    }

private:
    PlaceHolderAttributes(const std::filesystem::path &absolutePath)
       : absolutePath(absolutePath)
    {
    }

    PlaceHolderAttributes(const std::filesystem::path &absolutePath, const std::string &etag, const std::string &fileId, std::size_t size,
        OpenVfsConstants::States state, OpenVfsConstants::PinStates pinState)
        : absolutePath(absolutePath)
        , etag(etag)
        , fileId(fileId)
        , size(size)
        , state(state)
        , pinState(pinState)
        , _ok(true)
    {
    }

    bool _ok = false;
};
}
