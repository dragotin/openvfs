// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 Hannah von Reth <h.vonreth@opencloud.eu>

#pragma once
#include "openvfs_export.h"

#include <filesystem>
#include <optional>
#include <string>

namespace Xattr {
int OPENVFS_EXPORT getxattr(const std::filesystem::path &path, const char *name, char *value, size_t size);
int OPENVFS_EXPORT setxattr(const std::filesystem::path &path, const char *name, const char *value, size_t size, int flags);
int OPENVFS_EXPORT listxattr(const std::filesystem::path &path, char *list, size_t size);
int OPENVFS_EXPORT removexattr(const std::filesystem::path &path, const char *name);


namespace CPP {
    std::optional<std::string> OPENVFS_EXPORT getxattr(const std::filesystem::path &path, std::string_view name);
}
}
