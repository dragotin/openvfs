#ifndef STRTOOLS_H
#define STRTOOLS_H

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Klaas Freitag <k.freitag@opencloud.eu>

#pragma once
#include <string>
#include <vector>

namespace StrTools {
    std::vector<std::string> split(const std::string &str, char delimiter);
}


#endif // STRTOOLS_H
