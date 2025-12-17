// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 Hannah von Reth <h.vonreth@opencloud.eu>

#pragma once
#include <filesystem>
#include <optional>
#include <string>

namespace Xattr {
int getxattr(const std::filesystem::path &path, const char *name, char *value, size_t size);
int setxattr(const std::filesystem::path &path, const char *name, const char *value, size_t size, int flags);
int listxattr(const std::filesystem::path &path, char *list, size_t size);
int removexattr(const std::filesystem::path &path, const char *name);


namespace CPP {
    std::optional<std::string> getxattr(const std::filesystem::path &path, const std::string &name);
}
}
