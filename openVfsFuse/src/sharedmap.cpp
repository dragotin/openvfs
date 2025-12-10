/*
 * openvfsfuse - a Fuse layer to handle virtual filesystem items of cloud storage
 * Copyright (C) 2025  Klaas Freitag <k.freitag@opencloud.eu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "sharedmap.h"

SharedMap::SharedMap() { }

void SharedMap::insert(int key, const HydJob &value)
{
    std::lock_guard<std::mutex> lock(_mutex);
    _data[key] = value;
}

bool SharedMap::get(int key, HydJob &outValue)
{
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _data.find(key);
    if (it != _data.end()) {
        outValue = it->second;
        return true;
    }
    return false;
}

bool SharedMap::set(int key, const HydJob &value)
{
    std::lock_guard<std::mutex> lock(_mutex);

    auto it = _data.find(key);
    if (it != _data.end()) {
        _data[key] = value;
        return true;
    }
    return false;
}

bool SharedMap::remove(int id)
{
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _data.find(id);
    if (it != _data.end()) {
        _data.erase(id);
        return true;
    }
    return false;
}

void SharedMap::setDesktopClientPid(long pid)
{
    std::lock_guard<std::mutex> lock(_mutex);
    _pid = pid;
}

long SharedMap::desktopClientPid()
{
    std::lock_guard<std::mutex> lock(_mutex);
    return _pid;
}

void SharedMap::printAll()
{
    std::lock_guard<std::mutex> lock(_mutex);
    for (auto &[k, v] : _data) {
        std::cout << k << ": " << v.state << "\n";
    }
}
