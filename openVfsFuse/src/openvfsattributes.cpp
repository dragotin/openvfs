// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2025 Hannah von Reth <h.vonreth@opencloud.eu>

#include "openvfsattributes.h"

#include "xattr.h"

#include "nlohmann/json.hpp"

#include <iostream>


std::vector<uint8_t> OpenVfsAttributes::PlaceHolderAttributes::toData() const
{
    using namespace OpenVfsConstants;
    assert(*this);
    return nlohmann::json::to_msgpack({{name(Attributes::Etag), etag}, {name(Attributes::FileId), fileId}, {name(Attributes::Size), size},
        {name(Attributes::State), state}, {name(Attributes::PinState), pinState}});
}

OpenVfsAttributes::PlaceHolderAttributes OpenVfsAttributes::PlaceHolderAttributes::fromData(
    const std::filesystem::path &absolutePath, const std::vector<uint8_t> &d)
{
    using namespace OpenVfsConstants;
    if (d.empty()) {
        return {absolutePath};
    }
    const auto j = nlohmann::json::from_msgpack(d);
    return {absolutePath, j.at(name(Attributes::Etag)), j.at(name(Attributes::FileId)), j.at(name(Attributes::Size)), j.at(name(Attributes::State)),
        j.at(name(Attributes::PinState))};
}

std::optional<OpenVfsAttributes::PlaceHolderAttributes> OpenVfsAttributes::PlaceHolderAttributes::frommAttributes(const std::filesystem::path &absolutePath)
{
    const auto data = Xattr::CPP::getxattr(absolutePath, OpenVfsConstants::XAttributeNames::Data);
    if (!data.has_value()) {
        std::cerr << "No placeholder attributes found for: " << absolutePath << std::endl;
        return std::nullopt;
    }
    return fromData(absolutePath, std::vector<uint8_t>{data.value().cbegin(), data.value().cend()});
}

std::size_t OpenVfsAttributes::PlaceHolderAttributes::realSize() const
{
    auto size = Xattr::CPP::getxattr(absolutePath, OpenVfsConstants::XAttributeNames::RealSize);
    if (!size) {
        // the fuse layer is not available, so we can use the actual file size
        return std::filesystem::file_size(absolutePath);
    }
    return std::stol(size.value());
}
