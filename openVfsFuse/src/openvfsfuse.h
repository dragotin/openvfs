/*
 * openvfsfuse - a Fuse layer to handle virtual filesystem items of cloud storage
 * Copyright (C) 2023  Klaas Freitag <kfreitag@owncloud.com>
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

/*
 * This work is based on the nice work of Rémi Flament - remipouak at gmail.com
 * called loggedFS: https://github.com/rflament/loggedfs
 */

#ifdef linux
/* For pread()/pwrite() */
#define _X_SOURCE 500
#endif

#include <filesystem>
#include <vector>

int initializeOpenVFSFuse(const std::filesystem::path &mountPoint, const std::vector<std::string> &fuseArgs);
void openvfsfuse_log(const std::string &path, const char *action, int returncode, const char *format, ...);
