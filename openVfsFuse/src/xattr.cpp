// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 Hannah von Reth <h.vonreth@opencloud.eu>

#include "xattr.h"

#include "openvfsfuse.h"

#include <optional>
#include <sys/xattr.h>

int Xattr::getxattr(const std::string &path, const char *name, char *value, size_t size)
{
    ssize_t res = lgetxattr(path.c_str(), name, value, size);
    if (res < 0 && errno == ENODATA) {
        res = 0;
    }
    // dont log "attrib not available" as error
    openvfsfuse_log(path, "getxattr", res, "attrib name %s %s", name, errno == ENODATA ? "(attrib not found)" : value);
    if (res < 0) {
        return -errno;
    }
    return static_cast<int>(res);
}

std::optional<std::string> Xattr::CPP::getxattr(const std::string &path, const std::string &name)
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
