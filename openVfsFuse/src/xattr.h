// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 Hannah von Reth <h.vonreth@opencloud.eu>

#pragma once
#include <optional>
#include <string>

namespace Xattr {
int getxattr(const std::string &path, const char *name, char *value, size_t size);

namespace CPP {
    std::optional<std::string> getxattr(const std::string &path, const std::string &name);
}
}
