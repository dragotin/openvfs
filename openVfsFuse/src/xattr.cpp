// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 Hannah von Reth <h.vonreth@opencloud.eu>

#include "xattr.h"

#include <assert.h>
#include <format>

#include "openvfsfuse.h"

#include <optional>
#include <sys/xattr.h>

int Xattr::getxattr(const std::filesystem::path &path, const char *name, char *value, size_t size)
{
    ssize_t res = lgetxattr(path.c_str(), name, value, size);

    // dont log "attrib not available" as error
    if (res < 0 && errno == ENODATA) {
        openvfsfuse_log(path, "getxattr", 0, std::format("attrib {}: not found", name).c_str());

    } else {
        // use string view to ensure termination at size
        openvfsfuse_log(path, "getxattr", res, std::format("attrib {}: {}", name, value ? std::string_view(value, std::max<ssize_t>(0, res)) : "null").c_str());
    }

    if (res < 0) {
        return -errno;
    }

    return static_cast<int>(res);
}

std::optional<std::string> Xattr::CPP::getxattr(const std::filesystem::path &path, const std::string &name)
{
    std::string value;
    int res = 0;
    do {
        value.resize(value.size() + 255);
        res = Xattr::getxattr(path, name.c_str(), value.data(), value.size());
        if (res >= 0) {
            value.resize(res);
            return value;
        }
    } while (res == -ERANGE);
    return {};
}
