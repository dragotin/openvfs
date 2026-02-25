// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hannah von Reth <h.vonreth@opencloud.eu>

#include "../openvfsattributes.h"
#include "../xattr.h"


#include <filesystem>
#include <format>
#include <iostream>

namespace {
OpenVfsAttributes::PlaceHolderAttributes getPlaceholderAttribs(const std::filesystem::path &path)
{
    const auto data = Xattr::CPP::getxattr(path, std::string(OpenVfsConstants::XAttributeNames::Data));
    return OpenVfsAttributes::PlaceHolderAttributes::fromData(
        path, data ? std::vector<uint8_t>{data.value().cbegin(), data.value().cend()} : std::vector<uint8_t>{});
}

void stat(const std::filesystem::directory_entry &entry)
{
    const auto data = getPlaceholderAttribs(entry.path());
    std::cout << std::format("{:<60} {:^4} {:>10} {:>10} {:>10} {:>10} {:<33} {}", entry.path().filename().native(), data.validate() ? "✅" : "❌", data.size,
        data.realSize(), OpenVfsConstants::name(data.state), OpenVfsConstants::name(data.pinState), data.etag, data.fileId)
              << std::endl;
}
}

int main(int argc, char *argv[])
{
    if (argc == 2) {
        const auto entry = std::filesystem::directory_entry(argv[1]);
        std::cout << "OpenVfs Stat: " << entry.path() << std::endl;
        std::cout << std::format(
            "{:<60} {:<4} {:<10} {:<10} {:<10} {:<10} {:<33} {}", "Path", "Valid", "Size", "ActualSize", "State", "PinState", "Etag", "FileId")
                  << std::endl;
        if (!entry.exists()) {
            std::cout << entry.path() << " does not exist" << std::endl;
            return -1;
        }
        if (entry.is_directory()) {
            for (const auto &child : std::filesystem::directory_iterator(entry)) {
                stat(child);
            }
            return 0;
        } else {
            stat(entry);
        }
    }
    return -1;
}
