// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hannah von Reth <h.vonreth@opencloud.eu>
#pragma once
#include "3rdparty/json.hpp"

namespace OpenVfsAttributes
{
    struct PlaceHolderAttributes
    {
        std::filesystem::path absolutePath;
        std::string etag;
        std::string fileId;
        std::size_t size = 0;
        std::string action;
        std::string state;
        std::string pinState;

        bool isOk() const { return !absolutePath.empty(); }

        operator bool() const { return isOk(); }

        nlohmann::json toJson() const
        {
            return nlohmann::json{{"etag", etag}, {"fileId", fileId}, {"size", size}, {"action", action}, {"state", state}, {"pinState", pinState}};
        }

        static PlaceHolderAttributes fromJson(const std::filesystem::path &absolutePath, const nlohmann::json &j)
        {
            return PlaceHolderAttributes {
                .absolutePath=absolutePath,
                .etag = j.at("etag"),
                .fileId = j.at("fileId"),
                .size = j.at("size"),
                .action = j.at("action"),
                .state = j.at("state"),
                .pinState = j.at("pinState"),
            };
        }
    };
}
