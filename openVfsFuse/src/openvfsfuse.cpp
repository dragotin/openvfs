/*
* openvfsfuse - a Fuse layer to handle virtual filesystem items of cloud storage
* Copyright (C) 2023  Klaas Freitag <kfreitag@owncloud.com>
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

/*
 * This work is based on the nice work of Rémi Flament - remipouak at gmail.com
 * called loggedFS: https://github.com/rflament/loggedfs
 */

#ifdef linux
/* For pread()/pwrite() */
#define _X_SOURCE 500
#endif

#include <fuse3/fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/statfs.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "json.hpp"
#include "socketthread.h"
#include "sharedmap.h"

#include <stdarg.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <stdexcept>
#include <iostream>

#include <cstring>
#include <sstream>

#include "openvfsfuse.h"
#include "flags.h"


using json = nlohmann::json;
using namespace std;

#define PUSHARG(ARG)                      \
    assert(out->fuseArgc < MaxFuseArgs); \
    out->fuseArgv[out->fuseArgc++] = ARG

/* ========== Prototypes */
static bool isAbsolutePath(const char *fileName);

static int openVFSfuse_setxattr(const char *orig_path, const char *name, const char *value,
                                size_t size, int flags);

static int openVFSfuse_getxattr(const char *orig_path, const char *name, char *value,
                                size_t size);

static void *openVFSfuse_init(struct fuse_conn_info *info, fuse_config *cfg);

static int openVFSfuse_getattr(const char *orig_path, struct stat *stbuf, fuse_file_info *fi);

static int openVFSfuse_access(const char *orig_path, int mask);

static int openVFSfuse_readlink(const char *orig_path, char *buf, size_t size);

static int openVFSfuse_readdir(const char *orig_path, void *buf, fuse_fill_dir_t filler,
                               off_t offset, fuse_file_info *fi, fuse_readdir_flags);
static int openVFSfuse_mknod(const char *orig_path, mode_t mode, dev_t rdev);

static int openVFSfuse_mkdir(const char *orig_path, mode_t mode);

static int openVFSfuse_unlink(const char *orig_path);

static int openVFSfuse_rmdir(const char *orig_path);

static int openVFSfuse_symlink(const char *from, const char *orig_to);

static int openVFSfuse_rename(const char *orig_from, const char *orig_to, unsigned int flags);

static int openVFSfuse_link(const char *orig_from, const char *orig_to);

static int openVFSfuse_chmod(const char *orig_path, mode_t mode,fuse_file_info*);

static int openVFSfuse_chown(const char *orig_path, uid_t uid, gid_t gid, fuse_file_info*);

static int openVFSfuse_truncate(const char *orig_path, off_t size, fuse_file_info*);

static int openVFSfuse_utimens(const char *orig_path, const struct timespec ts[2], fuse_file_info *);

static int openVFSfuse_open(const char *orig_path, struct fuse_file_info *fi);

static int openVFSfuse_read(const char *orig_path, char *buf, size_t size, off_t offset,
                            struct fuse_file_info *fi);

static int openVFSfuse_write(const char *orig_path, const char *buf, size_t size,
                             off_t offset, struct fuse_file_info *fi);

static int openVFSfuse_statfs(const char *orig_path, struct statvfs *stbuf);

static int openVFSfuse_release(const char *orig_path, struct fuse_file_info *fi);
static int openVFSfuse_fsync(const char *orig_path, int isdatasync,
                             struct fuse_file_info *fi);


#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int openVFSfuse_setxattr(const char *orig_path, const char *name, const char *value,
                                size_t size, int flags);

static int openVFSfuse_getxattr(const char *orig_path, const char *name, char *value,
                                size_t size);
static int openVFSfuse_listxattr(const char *orig_path, char *list, size_t size);

static int openVFSfuse_removexattr(const char *orig_path, const char *name);
#endif /* HAVE_SETXATTR */


static int savefd;

static SharedMap _jobs;
static SocketThread _socketThread("SocketThread", _jobs);

static int _transfer_id{12};

const int MaxFuseArgs = 32;
struct openVFSfuse_Args
{
    char *mountPoint; // where the users read files
    bool isDaemon; // true == spawn in background, log to syslog except if log file parameter is set
    bool vfsOwnerOk;
    const char *fuseArgv[MaxFuseArgs];
    int fuseArgc;
};

static openVFSfuse_Args *openvfsfuseArgs = new openVFSfuse_Args;

struct openVFSPlaceHolderAttribs
{
    std::string absolutePath;
    std::string etag;
    std::string fileId;
    std::size_t fSize;
    std::string action;
    std::string state;
    std::string pinState;

    bool isOk() const { return !absolutePath.empty(); }
};

/* == Prototypes == */
static int openVFSfuse_setxattr(const char *orig_path, const char *name, const char *value,
                                size_t size, int flags);

static int openVFSfuse_getxattr(const char *orig_path, const char *name, char *value,
                                size_t size);

static bool ends_with(const std::string& str, const char* suffix, unsigned suffixLen)
{
    return str.size() >= suffixLen && str.compare(str.size()-suffixLen, suffixLen, suffix, suffixLen) == 0;
}
/* - Prototypes end - */

/*
 * Returns the name of the process which accessed the file system.
 */
static char *getcallername()
{
    char filename[100];
    sprintf(filename, "/proc/%d/cmdline", fuse_get_context()->pid);
    FILE *proc;
    char cmdline[256] = "";

    if ((proc = fopen(filename, "rt")) == NULL)
        return NULL;
    else
    {
        fread(cmdline, sizeof(cmdline), 1, proc);
        fclose(proc);
    }

    return strdup(cmdline);
}

static void openvfsfuse_log(const std::string& path, const char *action, const int returncode, const char *format, ...)
{
    // FIXME - whitelist of pathes that are not logged at all?
    if (path == "./.OpenCloudSync.log") return;

    va_list args;
    char *buf = nullptr;
    va_start(args, format);
    vasprintf(&buf, format, args);
    va_end(args);

    std::cout << path << " [ pid = " << fuse_get_context()->pid << " " << getcallername() << " uuid = " << fuse_get_context()->uid << " ]" << buf << (returncode >=0 ? "SUCCESS" : "FAILURE") << std::endl;
    free(buf);
}

static bool isAbsolutePath(const char *fileName)
{
    if (fileName && fileName[0] != '\0' && fileName[0] == '/')
        return true;
    else
        return false;
}

static std::string getAbsolutePath(const char *path)
{
    std::string s{openvfsfuseArgs->mountPoint};
    s += path;

    return s;
}

static std::string absoluteToRelativePath(const char *path)
{
    std::string s;

    int len = strlen(path)-strlen(openvfsfuseArgs->mountPoint);

    if (len < 1) return s;

    s += ".";
    s += (path + strlen(openvfsfuseArgs->mountPoint));
    return s;
}

static std::string getRelativePath(const char *path)
{
    std::string s(".");
    s.append(path);

    // Why is this happening? It's from the original code...
    int res = fchdir(savefd);

    // what is that for?
    if (res < 0 && errno != EBADF)
    {
        // FIXME proper log
        printf("** ERROR fchdir: %d  - %d\n", savefd, errno);
    }

    return s;
}

static void *openVFSfuse_init(struct fuse_conn_info *info, fuse_config *cfg)
{
    fchdir(savefd);

    openvfsfuse_log("/path", "_init", 1, "**** INIT called");

    return NULL;
}

openVFSPlaceHolderAttribs get_placeholder_attribs(const char *orig_path)
{
    openVFSPlaceHolderAttribs attr{};

    const size_t size = 254;
    char val[size] = {};

    // make sure the owner is correct. That means the xattr starts with
    // the word "opencloud".
    if (!openvfsfuseArgs->vfsOwnerOk) {
        openvfsfuse_log("/path", "_init", 1, "**** INIT called");

        return attr;
    }

    attr.absolutePath = getAbsolutePath(orig_path);

    int read = openVFSfuse_getxattr(orig_path, "user.openvfs.etag", val, size);
    if (read > 0) {
        attr.etag = std::string(val, read);
    }

    read = openVFSfuse_getxattr(orig_path, "user.openvfs.fileid", val, size);
    if (read > 0) {
        attr.fileId = std::string(val, read);
    }
    read = openVFSfuse_getxattr(orig_path, "user.openvfs.fsize", val, size);
    char *pEnd;
    if (read <= 0) {
        attr.fSize = 0;
    } else {
        attr.fSize = strtoul(val, &pEnd, 10);
    }

    read = openVFSfuse_getxattr(orig_path, "user.openvfs.action", val, size);
    if (read > 0) {
        attr.action = std::string(val, read);
    }

    read = openVFSfuse_getxattr(orig_path, "user.openvfs.state", val, size);
    if (read > 0) {
        attr.state = std::string(val, read);
    }

    read = openVFSfuse_getxattr(orig_path, "user.openvfs.pinstate", val, size);
    if (read > 0) {
        attr.pinState = std::string(val, read);
    }
    return attr;
}

static int openVFSfuse_getattr(const char *orig_path, struct stat *stbuf, fuse_file_info *fi)
{
    int res;

    const auto path = getRelativePath(orig_path);
    res = lstat(path.c_str(), stbuf);
    // const auto attribs = get_placeholder_attribs(orig_path);
    char val[255] = {};

    // if (stbuf->st_size == 0) {    optimize later on
    int read = openVFSfuse_getxattr(orig_path, "user.openvfs.fsize", val, 255);
    char *pEnd{nullptr};
    if (read >= 0) {
        stbuf->st_size = strtoul(val, &pEnd, 10);
    }

    if (res == -1)
        return -errno;

    return 0;
}

static int openVFSfuse_access(const char *orig_path, int mask)
{
    int res;

    const auto path = getRelativePath(orig_path);
    res = access(path.c_str(), mask);
    openvfsfuse_log(path.c_str(), "access", res, "");
    if (res == -1)
        return -errno;

    return 0;
}

static int openVFSfuse_readlink(const char *orig_path, char *buf, size_t size)
{
    int res;

    const auto path = getRelativePath(orig_path);
    res = readlink(path.c_str(), buf, size - 1);
    openvfsfuse_log(path.c_str(), "readlink", res, "readlink");

    if (res == -1)
        return -errno;

    buf[res] = '\0';

    return 0;
}

static int openVFSfuse_readdir(const char *orig_path, void *buf, fuse_fill_dir_t filler,
                               off_t offset, fuse_file_info *fi, fuse_readdir_flags)
{
    DIR *dp;
    struct dirent *de;
    int res;

    (void)offset;
    (void)fi;

    const auto path = getRelativePath(orig_path);

    dp = opendir(path.c_str());
    if (dp == NULL)
    {
        res = -errno;
        openvfsfuse_log(path.c_str(), "readdir", -1, "");

        return res;
    }

    while ((de = readdir(dp)) != NULL)
    {
        struct stat st = {};
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0, fuse_fill_dir_flags::FUSE_FILL_DIR_DEFAULTS)) {
            break;
        }
    }

    closedir(dp);
    openvfsfuse_log(path.c_str(), "readdir", 0, "");


    return 0;
}

static int openVFSfuse_mknod(const char *orig_path, mode_t mode, dev_t rdev)
{
    int res;
    const auto path = getRelativePath(orig_path);

    if (S_ISREG(mode)) {
        res = open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY, mode);
        openvfsfuse_log(path.c_str(), "mknod", res, "mknod %o S_IFREG (normal file creation)", mode);
        if (res >= 0)
            res = close(res);
    } else if (S_ISFIFO(mode)) {
        res = mkfifo(path.c_str(), mode);
        openvfsfuse_log(path.c_str(), "mkfifo", res, "mkfifo %o S_IFFIFO (fifo creation)", mode);
    } else {
        res = mknod(path.c_str(), mode, rdev);
        if (S_ISCHR(mode)) {
            openvfsfuse_log(path.c_str(), "mknod", res, "mknod %o (character device creation)", mode);
        }
        /*else if (S_IFBLK(mode))
        {
        openvfsfuse_log(path.c_str(),"mknod",res,"mknod %o (block device creation)", mode);
        }*/
        else
            openvfsfuse_log(path.c_str(), "mknod", res, "mknod %o", mode);
    }


    if (res == -1) {

        return -errno;
    } else {
        lchown(path.c_str(), fuse_get_context()->uid, fuse_get_context()->gid);
    }



    return 0;
}

static int openVFSfuse_mkdir(const char *orig_path, mode_t mode)
{
    int res;
    const auto path = getRelativePath(orig_path);
    res = mkdir(path.c_str(), mode);
    openvfsfuse_log(path.c_str(), "mkdir", res, "mkdir mode %o", mode);

    if (res == -1)
    {

        return -errno;
    }
    else
        lchown(path.c_str(), fuse_get_context()->uid, fuse_get_context()->gid);

    return 0;
}

static int openVFSfuse_unlink(const char *orig_path)
{
    int res;
    const auto path = getRelativePath(orig_path);
    res = unlink(path.c_str());
    openvfsfuse_log(path.c_str(), "unlink", res, "");

    if (res == -1)
        return -errno;

    return 0;
}

static int openVFSfuse_rmdir(const char *orig_path)
{
    int res;
    const auto path = getRelativePath(orig_path);
    res = rmdir(path.c_str());
    openvfsfuse_log(path.c_str(), "rmdir", res, "");

    if (res == -1)
        return -errno;
    return 0;
}

static int openVFSfuse_symlink(const char *from, const char *orig_to)
{
    int res;

    const auto to = getRelativePath(orig_to);

    res = symlink(from, to.c_str());

    openvfsfuse_log(to, "symlink", res, "symlink from %s to %s", from, to.c_str());

    if (res == -1) {
        return -errno;
    } else {
        lchown(to.c_str(), fuse_get_context()->uid, fuse_get_context()->gid);
    }

    return 0;
}

static int openVFSfuse_rename(const char *orig_from, const char *orig_to, unsigned int flags)
{
    int res;
    const auto from = getRelativePath(orig_from);
    const auto to = getRelativePath(orig_to);
    res = rename(from.c_str(), to.c_str());
    openvfsfuse_log(from, "rename", res, "rename %s to %s", from.c_str(), to.c_str());

    if (res == -1) {
        return -errno;
    }
    return 0;
}

static int openVFSfuse_link(const char *orig_from, const char *orig_to)
{
    int res;

    const auto from = getRelativePath(orig_from);
    const auto to = getRelativePath(orig_to);

    res = link(from.c_str(), to.c_str());
    openvfsfuse_log(to, "link", res, "hard link from %s to %s", from.c_str(), to.c_str());

    if (res == -1) {
        return -errno;
    } else {
        lchown(to.c_str(), fuse_get_context()->uid, fuse_get_context()->gid);
    }

    return 0;
}

static int openVFSfuse_chmod(const char *orig_path, mode_t mode, fuse_file_info*)
{
    int res;
    const auto path = getRelativePath(orig_path);
    res = chmod(path.c_str(), mode);
    openvfsfuse_log(path.c_str(), "chmod", res, "chmod to %o", mode);

    if (res == -1) {
        return -errno;
    }

    return 0;
}

static char *getusername(uid_t uid)
{
    struct passwd *p = getpwuid(uid);
    if (p != NULL)
        return p->pw_name;
    return NULL;
}

static char *getgroupname(gid_t gid)
{
    struct group *g = getgrgid(gid);
    if (g != NULL)
        return g->gr_name;
    return NULL;
}

static int openVFSfuse_chown(const char *orig_path, uid_t uid, gid_t gid,fuse_file_info*)
{
    int res;
    const auto path = getRelativePath(orig_path);
    res = lchown(path.c_str(), uid, gid) == -1 ? -errno : 0;

    char *username = getusername(uid);
    char *groupname = getgroupname(gid);

    if (username != NULL && groupname != NULL)
        openvfsfuse_log(path.c_str(), "chown", res, "chown to %d:%d %s:%s", uid, gid, username, groupname);
    else
        openvfsfuse_log(path.c_str(), "chown", res, "chown to %d:%d", uid, gid);

    return res;
}

static int openVFSfuse_truncate(const char *orig_path, off_t size, fuse_file_info*)
{
    int res;

    const auto path = getRelativePath(orig_path);
    res = truncate(path.c_str(), size);
    openvfsfuse_log(path.c_str(), "truncate", res, "truncate to %d bytes", size);

    if (res == -1) {
        return -errno;
    }

    return 0;
}

static int openVFSfuse_utimens(const char *orig_path, const struct timespec ts[2], fuse_file_info *)
{
    int res;
    const auto path = getRelativePath(orig_path);

    res = utimensat(AT_FDCWD, path.c_str(), ts, AT_SYMLINK_NOFOLLOW);

    openvfsfuse_log(path.c_str(), "utimens", res, "");

    if (res == -1) {
        return -errno;
    }

    return 0;
}

static int openVFSfuse_open(const char *orig_path, struct fuse_file_info *fi)
{
    int res{0};
    const auto path = getRelativePath(orig_path);

    const auto opener = getcallername();
    static auto openFlags = []{
        auto f = OFlags<typeof(fi->flags)>("OpenFlags");
        ADD_O_FLAG(f, O_RDONLY);
        ADD_O_FLAG(f, O_WRONLY);
        ADD_O_FLAG(f, O_RDWR);
        ADD_O_FLAG(f, O_APPEND);
        ADD_O_FLAG(f, O_CREAT);
        ADD_O_FLAG(f, O_DIRECTORY);
        ADD_O_FLAG(f, O_EXCL);
        ADD_O_FLAG(f, O_NOCTTY);
        ADD_O_FLAG(f, O_NOFOLLOW);
        ADD_O_FLAG(f, O_TMPFILE);
        ADD_O_FLAG(f, O_APPEND);
        ADD_O_FLAG(f, O_TRUNC);
        f.names[0100000] = "O_LARGEFILE";

        return f;
    }();


    stringstream s;
    s<< OFlag(openFlags, fi->flags);
    openvfsfuse_log(path.c_str(), "open", res, "open %s %s by %s", s.str().data(), path.c_str(), opener);

    auto attribs = get_placeholder_attribs(orig_path);

    if (!attribs.isOk()) {
        openvfsfuse_log(path.c_str(), "open", 0, "Not a placeholder file");
    }

    // The desktop client must not be blocked from accessing the file
    // to be able to overwrite it.
    long desktopClientPid = _jobs.desktopClientPid();
    long callerPid = fuse_get_context()->pid;

    const bool desktopClient = (callerPid == desktopClientPid);
    if (desktopClient) {
        cout << "Desktop client wants to access file - bypassing" << endl;
    }

    if (!desktopClient && attribs.state.compare("virtual") == 0) {
        // the file is virtual. It will be hydrated if the calling instance
        // is not on the ignore list

        bool ok{true};

        // ignore list of apps that must not cause a hydration
        if (ends_with(opener, "kioworker", 9) || ends_with(opener, "dolphin", 7)) {
            ok = false;
            openvfsfuse_log(path.c_str(), "open", 0, "Blocking hydration for kio_worker");
            return -EPERM;
        }

        // check if the desktop client calls in
        ok = ok && (callerPid != desktopClientPid);

        if (ok) {
            ++_transfer_id;
            // Create message to send to worker thread 1
            std::shared_ptr<MsgData> msgData(new MsgData());
            msgData->msg = "V2/HYDRATE_FILE";
            msgData->file = attribs.absolutePath;
            msgData->fileId = attribs.fileId;
            msgData->requester = getcallername();
            msgData->id = _transfer_id; // attention: _transfer_id is global and can change!

            _socketThread.PostMsg(msgData); // push hydration request to msg thread

            // Now Loop in this thread until the shared map of running jobs does not
            // longer contain the transfer_id
            int cnt{0};
            int state{1};
            const auto MaxCnt{500};
            std::chrono::duration waitTime{20ms};
            std::chrono::duration dur{30ms};

            while(state == 1 && cnt++ < MaxCnt) {
                this_thread::sleep_for(waitTime); // sleep for some time
                waitTime += dur;
                dur += waitTime;

                // check shared map and see if the id has changed to 0, which means success
                // the value is changed in the other thread and fetched here
                HydJob hj;

                if (! _jobs.get(msgData->id, hj)) {
                    // The job is no longer there :-/
                    openvfsfuse_log(path.c_str(), "open", 1, "Job queue does not have job %d", msgData->id);
                    state = -1;
                } else {
                    state = hj.state;
                    openvfsfuse_log(path.c_str(), "open", 1, "Found in job queue %d", state);

                    // With all the state values except 1, the loop is left
                    if (state == 0) {
                        // success!
                        openvfsfuse_log(path.c_str(), "open", 1, "Sucessfully finished job %d", msgData->id);
                    } else if (state == 1) {
                        // still running
                    } else if (state == -1) {
                        // fail
                        openvfsfuse_log(path.c_str(), "open", 0, "Failed job %d", msgData->id);
                    } else if (state == 2) {
                        // timeout
                        openvfsfuse_log(path.c_str(), "open", 0, "Job %d timed out", msgData->id);
                    }
                }
            }


            // remove the job regardless of the result
            _jobs.remove(msgData->id);

            if (state == -1 || state == 2) {
                // Fail, job with ID was errornous
                openvfsfuse_log(path.c_str(), "open", 1, "ERROR while retrieving: %d", state);
                return -ENOENT;
            }

            if (cnt >= MaxCnt) {
                openvfsfuse_log(path.c_str(), "open", MaxCnt, "TIMEOUT - no answer from client");
                return -ENOENT;
            }
        }
        openvfsfuse_log(path.c_str(), "open", 0, "-- open finished");
    }

    // File is not dehydrated and it is just going to be opened
    res = open(path.c_str(), fi->flags);

    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}

static int openVFSfuse_read(const char *orig_path, char *buf, size_t size, off_t offset,
                            struct fuse_file_info *fi)
{
    int res;
    const auto path = getRelativePath(orig_path);

    openvfsfuse_log(path.c_str(), "read", 0, "read %d bytes at offset %d", size, offset);
    res = pread(fi->fh, buf, size, offset);
    if (res == -1)
    {
        res = -errno;
        openvfsfuse_log(path.c_str(), "read", -1, "read %d bytes at offset %d", size, offset);
    }
    else
    {
        openvfsfuse_log(path.c_str(), "read", 0, "%d bytes read at offset %d", res, offset);
    }

    return res;
}

static int openVFSfuse_write(const char *orig_path, const char *buf, size_t size,
                             off_t offset, struct fuse_file_info *fi)
{
    int fd;
    int res;
    const auto path = getRelativePath(orig_path);
    (void)fi;

    fd = open(path.c_str(), O_WRONLY);
    if (fd == -1)
    {
        res = -errno;
        openvfsfuse_log(path.c_str(), "write", -1, "write %d bytes to %s at offset %d", size, path.c_str(), offset);

        return res;
    }
    else
    {
        openvfsfuse_log(path.c_str(), "write", 0, "write %d bytes to %s at offset %d", size, path.c_str(), offset);
    }

    res = pwrite(fd, buf, size, offset);

    if (res == -1)
        res = -errno;
    else
        openvfsfuse_log(path.c_str(), "write", 0, "%d bytes written to %s at offset %d", res, path.c_str(), offset);

    close(fd);


    return res;
}

static int openVFSfuse_statfs(const char *orig_path, struct statvfs *stbuf)
{
    int res;
    const auto path = getRelativePath(orig_path);
    res = statvfs(path.c_str(), stbuf);
    openvfsfuse_log(path.c_str(), "statfs", res, "");

    if (res == -1)
        return -errno;

    return 0;
}

static int openVFSfuse_release(const char *orig_path, struct fuse_file_info *fi)
{
    (void)orig_path;
    const auto path = getRelativePath(orig_path);

    openvfsfuse_log(path.c_str(), "close", 0, "");

    close(fi->fh);
    return 0;
}

static int openVFSfuse_fsync(const char *orig_path, int isdatasync,
                             struct fuse_file_info *fi)
{
    const auto path = getRelativePath(orig_path);

    (void)orig_path;
    (void)isdatasync;
    (void)fi;
    openvfsfuse_log(path.c_str(), "fsync", 0, "");

    return 0;
}

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int openVFSfuse_setxattr(const char *orig_path, const char *name, const char *value,
                                size_t size, int flags)
{
    const auto path = getRelativePath(orig_path);

    int res;
    res = lsetxattr(path.c_str(), name, value, size, flags);
    openvfsfuse_log(path.c_str(), "setxattr", res, "%s = %s", name, std::string(value, size).data());


    if (res == -1)
        return -errno;
    return 0;
}

static int openVFSfuse_getxattr(const char *orig_path, const char *name, char *value,
                                size_t size)
{
    const auto path = getRelativePath(orig_path);

    int res = lgetxattr(path.c_str(), name, value, size);

    // dont log "attrib not available" as error
    if (res > 0) res = 0;
    if (res < 0 && errno == ENODATA) {
        res = 0;
    }

    openvfsfuse_log(path.c_str(), "getxattr", res, "attrib name %s %s", name, errno == ENODATA ? "(attrib not found)":"");

    if (res == -1)
        return -errno;

    if (res < size) {
        value[res] = 0;
    }

    return res;
}

static int openVFSfuse_listxattr(const char *orig_path, char *list, size_t size)
{
    const auto path = getRelativePath(orig_path);
    int res = llistxattr(path.c_str(), list, size);
    openvfsfuse_log(path.c_str(), "listxattr", res, "");

    if (res == -1)
        return -errno;
    return res;
}

static int openVFSfuse_removexattr(const char *orig_path, const char *name)
{
    const auto path = getRelativePath(orig_path);

    int res = lremovexattr(path.c_str(), name);
    openvfsfuse_log(path.c_str(), "removexattr", 0, "remove %s", name);

    if (res == -1)
        return -errno;
    return 0;
}
#endif /* HAVE_SETXATTR */

static void usage(char *name)
{
    std::cerr << "Usage:" << std::endl //
    << name << " [-h] | [-f] [-p] [-e] /directory-mountpoint" << std::endl //
    <<  "Type 'man openvfsfuse' for more details" << std::endl;
}

static bool processArgs(int argc, char *argv[], openVFSfuse_Args *out)
{
    // set defaults
    out->isDaemon = true;

    out->fuseArgc = 0;

    // pass executable name through
    out->fuseArgv[0] = argv[0];
    ++out->fuseArgc;

    // leave a space for mount point, as FUSE expects the mount point before
    // any flags
    out->fuseArgv[1] = NULL;
    ++out->fuseArgc;
    opterr = 0;

    int res;

    bool got_p = false;

    // We need the "nonempty" option to mount the directory in recent FUSE's
    // because it's non empty and contains the files that will be logged.
    //
    // We need "use_ino" so the files will use their original inode numbers,
    // instead of all getting 0xFFFFFFFF . For example, this is required for
    // logging the ~/.kde/share/config directory, in which hard links for lock
    // files are verified by their inode equivalency.
    //
    // We need "atomic_o_trunc" option. if not, then FUSE will call truncate()
    // function before calling open(). if the option was set, the O_TRUNC flag
    // is passed to open() function. Without this flag, this will cause opening
    // files in gvfs to fail.
    // https://gitlab.gnome.org/GNOME/gvfs/-/blob/master/client/gvfsfusedaemon.c#L1045

#define COMMON_OPTS "attr_timeout=0,entry_timeout=0,negative_timeout=0"

    while ((res = getopt(argc, argv, "hpfe:")) != -1)
    {
        switch (res)
        {
        case 'h':
            usage(argv[0]);
            return false;
        case 'f':
            out->isDaemon = false;
            // this option was added in fuse 2.x
            PUSHARG("-f");
            std::cout << "openVFSfuse not running as a daemon" << std::endl;
            break;
        case 'p':
            PUSHARG("-o");
            PUSHARG("allow_other,default_permissions," COMMON_OPTS);
            got_p = true;
            std::cout << "openVFSfuse running as a public filesystem" <<  std::endl;
            break;
        case 'e':
            PUSHARG("-o");
            PUSHARG("nonempty");
            std::cout << "Using existing directory"<< std::endl;;
            break;
        default:
            assert(false);
            break;
        }
    }

    if (!got_p)
    {
        PUSHARG("-o");
        PUSHARG(COMMON_OPTS);
    }
#undef COMMON_OPTS

    if (optind + 1 <= argc)
    {
        out->mountPoint = argv[optind++];
        out->fuseArgv[1] = out->mountPoint;
    }
    else
    {
        std::cerr << "Missing mountpoint" << std::endl;;
        usage(argv[0]);
        return false;
    }

    // If there are still extra unparsed arguments, pass them onto FUSE..
    if (optind < argc)
    {
        assert(out->fuseArgc < MaxFuseArgs);

        while (optind < argc)
        {
            assert(out->fuseArgc < MaxFuseArgs);
            out->fuseArgv[out->fuseArgc++] = argv[optind];
            ++optind;
        }
    }

    if (!isAbsolutePath(out->mountPoint))
    {
        std::cerr << "You must use absolute paths (beginning with '/') for " << out->mountPoint << std::endl;
        return false;
    }

    return true;
}


int initializeOpenVFSFuse(int argc, char *argv[])
{
    umask(0);
    fuse_operations openVFSfuse_oper;
    // in case this code is compiled against a newer FUSE library and new
    // members have been added to fuse_operations, make sure they get set to
    // 0..
    memset(&openVFSfuse_oper, 0, sizeof(fuse_operations));
    openVFSfuse_oper.init = openVFSfuse_init;
    openVFSfuse_oper.getattr = openVFSfuse_getattr;
    openVFSfuse_oper.access = openVFSfuse_access;
    openVFSfuse_oper.readlink = openVFSfuse_readlink;
    openVFSfuse_oper.readdir = openVFSfuse_readdir;
    openVFSfuse_oper.mknod = openVFSfuse_mknod;
    openVFSfuse_oper.mkdir = openVFSfuse_mkdir;
    openVFSfuse_oper.symlink = openVFSfuse_symlink;
    openVFSfuse_oper.unlink = openVFSfuse_unlink;
    openVFSfuse_oper.rmdir = openVFSfuse_rmdir;
    openVFSfuse_oper.rename = openVFSfuse_rename;
    openVFSfuse_oper.link = openVFSfuse_link;
    openVFSfuse_oper.chmod = openVFSfuse_chmod;
    openVFSfuse_oper.chown = openVFSfuse_chown;
    openVFSfuse_oper.truncate = openVFSfuse_truncate;
    openVFSfuse_oper.utimens = openVFSfuse_utimens;
    openVFSfuse_oper.open = openVFSfuse_open;
    openVFSfuse_oper.read = openVFSfuse_read;
    openVFSfuse_oper.write = openVFSfuse_write;
    openVFSfuse_oper.statfs = openVFSfuse_statfs;
    openVFSfuse_oper.release = openVFSfuse_release;
    openVFSfuse_oper.fsync = openVFSfuse_fsync;
#ifdef HAVE_SETXATTR
    openVFSfuse_oper.setxattr = openVFSfuse_setxattr;
    openVFSfuse_oper.getxattr = openVFSfuse_getxattr;
    openVFSfuse_oper.listxattr = openVFSfuse_listxattr;
    openVFSfuse_oper.removexattr = openVFSfuse_removexattr;
#endif

    for (int i = 0; i < MaxFuseArgs; ++i)
        openvfsfuseArgs->fuseArgv[i] = NULL; // libfuse expects null args..

    if (processArgs(argc, argv, openvfsfuseArgs))
    {

        std::cout << "openVFSfuse starting at" << openvfsfuseArgs->mountPoint << "." << std::endl;

        // check ownership on the mountpoint
        openvfsfuseArgs->vfsOwnerOk = false;
        char value[255];
        int res = lgetxattr(openvfsfuseArgs->mountPoint, "user.openvfs.owner", value, 255);
        if (strncmp(value, "opencloud", 9) == 0) {
            openvfsfuseArgs->vfsOwnerOk = true;
        }

        if (res == -1) {
            std::cout << "Root directory does not have owner info" << std::endl;;
            // return -errno;
        }

        std::cout << "chdir to" << openvfsfuseArgs->mountPoint << std::endl;
        chdir(openvfsfuseArgs->mountPoint);
        savefd = open(".", 0);

        _socketThread.CreateThread();

#if (FUSE_USE_VERSION == 25)
        fuse_main(openvfsfuseArgs->fuseArgc,
                  const_cast<char **>(openvfsfuseArgs->fuseArgv), &openVFSfuse_oper);
#else
        fuse_main(openvfsfuseArgs->fuseArgc,
                  const_cast<char **>(openvfsfuseArgs->fuseArgv), &openVFSfuse_oper, NULL);
#endif

        std::cout << "openVFSfuse closing." << std::endl;
    }

    return 0;
}
