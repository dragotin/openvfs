// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hannah von Reth <h.vonreth@opencloud.eu>
#pragma once
#include "openvfconstants.h"
#include "openvfs_export.h"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace OpenVfsAttributes {
class OPENVFS_EXPORT PlaceHolderAttributes
{
public:
    /**
     * Creates a PlaceHolderAttributes object from a given absolute path.
     * It is assumed the file exists and is not a placeholder.
     * @param absolutePath
     */
    PlaceHolderAttributes(const std::filesystem::path &absolutePath)
        : absolutePath(absolutePath)
    {
    }

    std::filesystem::path absolutePath;
    std::string etag;
    std::string fileId;
    std::size_t size = 0;
    // assume an exisitng file by default
    OpenVfsConstants::States state = OpenVfsConstants::States::Hydrated;
    OpenVfsConstants::PinStates pinState = OpenVfsConstants::PinStates::Inherited;

    [[nodiscard]] bool isOk() const { return _ok; }

    operator bool() const { return isOk(); }

    [[nodiscard]] std::vector<uint8_t> toData() const;

    static PlaceHolderAttributes create(const std::filesystem::path &absolutePath, const std::string &etag, const std::string &fileId, std::size_t size)
    {
        using namespace OpenVfsConstants;
        return {absolutePath, etag, fileId, size, States::DeHydrated, PinStates::Inherited};
    }

    static PlaceHolderAttributes fromData(const std::filesystem::path &absolutePath, const std::vector<uint8_t> &d);
    static std::optional<PlaceHolderAttributes> frommAttributes(const std::filesystem::path &absolutePath);

    [[nodiscard]] std::size_t realSize() const;

    [[nodiscard]] bool validate() const
    {
        if (!_ok) {
            return false;
        }
        switch (state) {
        case OpenVfsConstants::States::Hydrated:
            return size == 0;
        case OpenVfsConstants::States::DeHydrated:
            return realSize() == 0;
        case OpenVfsConstants::States::Hydrating:
            return true;
        }
        return true;
    }

private:
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
