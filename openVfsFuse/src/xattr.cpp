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
#ifdef __APPLE__
    const ssize_t res = ::getxattr(path.c_str(), name, value, size, 0, XATTR_NOFOLLOW);
#else
    const ssize_t res = ::lgetxattr(path.c_str(), name, value, size);
#endif
    if (res < 0) {
        return -errno;
    }
    return static_cast<int>(res);
}

int Xattr::setxattr(const std::filesystem::path &path, const char *name, const char *value, size_t size, int flags)
{
#ifdef __APPLE__
    const auto res = ::setxattr(path.c_str(), name, value, size, flags, XATTR_NOFOLLOW);
#else
    const auto res = ::lsetxattr(path.c_str(), name, value, size, flags);
#endif

    if (res < 0) {
        return -errno;
    }
    return 0;
}

int Xattr::listxattr(const std::filesystem::path &path, char *list, size_t size)
{
#ifdef __APPLE__
    const auto res = ::listxattr(path.c_str(), list, size, XATTR_NOFOLLOW);
#else
    const auto res = ::llistxattr(path.c_str(), list, size);
#endif
    if (res < 0) {
        return -errno;
    }
    return res;
}

int Xattr::removexattr(const std::filesystem::path &path, const char *name)
{
#ifdef __APPLE__
    const auto res = ::removexattr(path.c_str(), name, XATTR_NOFOLLOW);
#else
    const auto res = ::lremovexattr(path.c_str(), name);
#endif
    if (res < 0) {
        return -errno;
    }
    return 0;
}

std::optional<std::string> Xattr::CPP::getxattr(const std::filesystem::path &path, std::string_view name)
{
    std::string value;
    int res = 0;
    do {
        value.resize(value.size() + 255);
        res = Xattr::getxattr(path, name.data(), value.data(), value.size());
        if (res >= 0) {
            value.resize(res);
            return value;
        }
    } while (res == -ERANGE);
    return {};
}
