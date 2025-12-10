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

#ifndef SHAREDMAP_H
#define SHAREDMAP_H

#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <thread>

struct HydJob
{
public:
    int state;
};

class SharedMap
{
public:
    SharedMap();
    void insert(int key, const HydJob &value);

    bool get(int key, HydJob &outValue);
    bool remove(int id);
    bool set(int key, const HydJob &value);

    void printAll();
    void setDesktopClientPid(long pid);
    long desktopClientPid();

private:
    std::map<int, HydJob> _data;
    std::mutex _mutex;
    long _pid;
};


#endif // SHAREDMAP_H
