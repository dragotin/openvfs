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

#include <fuse.h>
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
#include "easylogging++.h"
#include <stdarg.h>
#include <getopt.h>
#include <sys/time.h>
#include <pwd.h>
#include <grp.h>
#include "Config.h"
#include <stdexcept>
#include <iostream>

#include "openvfsfuse.h"

INITIALIZE_EASYLOGGINGPP

#define STR(X) #X
#define rAssert(cond)                                     \
    do                                                    \
    {                                                     \
        if ((cond) == false)                              \
        {                                                 \
            LOG(ERROR) << "Assert failed: " << STR(cond); \
            throw std::runtime_error(STR(cond));          \
        }                                                 \
    } while (false)

#define PUSHARG(ARG)                      \
    rAssert(out->fuseArgc < MaxFuseArgs); \
    out->fuseArgv[out->fuseArgc++] = ARG

using namespace std;

/* ========== Prototypes */
static bool isAbsolutePath(const char *fileName);

static int openVFSfuse_setxattr(const char *orig_path, const char *name, const char *value,
                             size_t size, int flags);

static int openVFSfuse_getxattr(const char *orig_path, const char *name, char *value,
                             size_t size);

static void *openVFSfuse_init(struct fuse_conn_info *info);

static int openVFSfuse_getattr(const char *orig_path, struct stat *stbuf);

static int openVFSfuse_access(const char *orig_path, int mask);

static int openVFSfuse_readlink(const char *orig_path, char *buf, size_t size);

static int openVFSfuse_readdir(const char *orig_path, void *buf, fuse_fill_dir_t filler,
                            off_t offset, struct fuse_file_info *fi);
static int openVFSfuse_mknod(const char *orig_path, mode_t mode, dev_t rdev);

static int openVFSfuse_mkdir(const char *orig_path, mode_t mode);

static int openVFSfuse_unlink(const char *orig_path);

static int openVFSfuse_rmdir(const char *orig_path);

static int openVFSfuse_symlink(const char *from, const char *orig_to);

static int openVFSfuse_rename(const char *orig_from, const char *orig_to);

static int openVFSfuse_link(const char *orig_from, const char *orig_to);

static int openVFSfuse_chmod(const char *orig_path, mode_t mode);

static int openVFSfuse_chown(const char *orig_path, uid_t uid, gid_t gid);

static int openVFSfuse_truncate(const char *orig_path, off_t size);

#if (FUSE_USE_VERSION == 25)
static int openVFSfuse_utime(const char *orig_path, struct utimbuf *buf);
#else
static int openVFSfuse_utimens(const char *orig_path, const struct timespec ts[2]);
#endif

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


static Config config;
static int savefd;
static el::base::DispatchAction dispatchAction = el::base::DispatchAction::NormalLog;
static const char *loggerId = "default";
static const char *additionalInfoFormat = " {%s} [ pid = %d %s uid = %d ]";
static el::Logger *defaultLogger;

const int MaxFuseArgs = 32;
struct openVFSfuse_Args
{
    char *mountPoint; // where the users read files
    char *configFilename;
    bool isDaemon; // true == spawn in background, log to syslog except if log file parameter is set
    bool logToSyslog;
    const char *fuseArgv[MaxFuseArgs];
    int fuseArgc;
};

static openVFSfuse_Args *openvfsfuseArgs = new openVFSfuse_Args;

/* Prototypes */
static int openVFSfuse_setxattr(const char *orig_path, const char *name, const char *value,
                             size_t size, int flags);

static int openVFSfuse_getxattr(const char *orig_path, const char *name, char *value,
                             size_t size);


static bool isAbsolutePath(const char *fileName)
{
    if (fileName && fileName[0] != '\0' && fileName[0] == '/')
        return true;
    else
        return false;
}

static char *getRelativePath(const char *path)
{
    char* fixed = new char[strlen(path)+2];

    int res = fchdir(savefd);

    if (res < 0 && errno != EBADF)
    {
        printf("** ERROR fchdir: %d\n", errno);
    }

    strcpy(fixed,".");
    strcat(fixed,path);

    return fixed;
}

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

static void openvfsfuse_log(const char *path, const char *action, const int returncode, const char *format, ...)
{
    const char *retname;

    if (returncode >= 0)
        retname = "SUCCESS";
    else
        retname = "FAILURE";

    if (config.shouldLog(path, fuse_get_context()->uid, action, retname))
    {
        va_list args;
        char *buf = NULL;
        char *additionalInfo = NULL;

        char *caller_name = getcallername();
        asprintf(&additionalInfo, additionalInfoFormat, retname, fuse_get_context()->pid, config.isPrintProcessNameEnabled() ? caller_name : "", fuse_get_context()->uid);

        va_start(args, format);
        vasprintf(&buf, format, args);
        va_end(args);

        if (returncode >= 0)
        {
            ELPP_WRITE_LOG(el::base::Writer, el::Level::Info, dispatchAction, "default") << buf << additionalInfo;
        }
        else
        {
            ELPP_WRITE_LOG(el::base::Writer, el::Level::Error, dispatchAction, "default") << buf << additionalInfo;
        }

        free(buf);
        free(additionalInfo);
        free(caller_name);
    }
}

static void *openVFSfuse_init(struct fuse_conn_info *info)
{
    fchdir(savefd);
    close(savefd);
    return NULL;
}

/*
 * checks if a file is hydrated by looking up the extended attribute "user.openvfs.state"
 * If it is set to "dehydrated" this indicates that the file is not present locally and
 * the size is read from an extended attr as well
 */
int check_if_dehydrated(const char *orig_path, struct stat *stbuf)
{
    const char *path = getRelativePath(orig_path);
    char val[30] = {};
    size_t size = 30;

    int res = openVFSfuse_getxattr(orig_path, "user.openvfs.state", val, size);
    openvfsfuse_log(path, "check_dehydrated", res, "state %s", val);

    if (strncmp(val, "dehydrated", 10) == 0) {
        res = openVFSfuse_getxattr(orig_path, "user.openvfs.fsize", val, size);

        char *endptr;
        unsigned long int value;

        value = strtoul(val, &endptr, 0);
        stbuf->st_size = value;
        openvfsfuse_log(path, "check_dehydrated", value, "xattr size is (%ld)", value);
    }


    delete[] path;
    return res;
}

static int openVFSfuse_getattr(const char *orig_path, struct stat *stbuf)
{
    int res;

    const char *path = getRelativePath(orig_path);
    res = lstat(path, stbuf);

    if (stbuf->st_size == 0L) {
        check_if_dehydrated(orig_path, stbuf);
    }

    openvfsfuse_log(path, "getattr", res, "getattr %s (%d)", path, res);
    delete[] path;
    if (res == -1)
        return -errno;

    return 0;
}

static int openVFSfuse_access(const char *orig_path, int mask)
{
    int res;

    char *path = getRelativePath(orig_path);
    res = access(path, mask);
    openvfsfuse_log(path, "access", res, "access %s", path);
    delete[] path;
    if (res == -1)
        return -errno;

    return 0;
}

static int openVFSfuse_readlink(const char *orig_path, char *buf, size_t size)
{
    int res;

    const char *path = getRelativePath(orig_path);
    res = readlink(path, buf, size - 1);
    openvfsfuse_log(path, "readlink", res, "readlink %s", path);
    delete[] path;
    if (res == -1)
        return -errno;

    buf[res] = '\0';

    return 0;
}

static int openVFSfuse_readdir(const char *orig_path, void *buf, fuse_fill_dir_t filler,
                            off_t offset, struct fuse_file_info *fi)
{
    DIR *dp;
    struct dirent *de;
    int res;

    (void)offset;
    (void)fi;

    char *path = getRelativePath(orig_path);

    dp = opendir(path);
    if (dp == NULL)
    {
        res = -errno;
        openvfsfuse_log(path, "readdir", -1, "readdir %s", path);
        delete[] path;
        return res;
    }

    while ((de = readdir(dp)) != NULL)
    {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0)) {
            break;
        }
    }

    closedir(dp);
    openvfsfuse_log(path, "readdir", 0, "readdir %s", path);
    delete[] path;

    return 0;
}

static int openVFSfuse_mknod(const char *orig_path, mode_t mode, dev_t rdev)
{
    int res;
    const char *path = getRelativePath(orig_path);

    if (S_ISREG(mode))
    {
        res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
        openvfsfuse_log(path, "mknod", res, "mknod %s %o S_IFREG (normal file creation)", path, mode);
        if (res >= 0)
            res = close(res);
    }
    else if (S_ISFIFO(mode))
    {
        res = mkfifo(path, mode);
        openvfsfuse_log(path, "mkfifo", res, "mkfifo %s %o S_IFFIFO (fifo creation)", path, mode);
    }
    else
    {
        res = mknod(path, mode, rdev);
        if (S_ISCHR(mode))
        {
            openvfsfuse_log(path, "mknod", res, "mknod %s %o (character device creation)", path, mode);
        }
        /*else if (S_IFBLK(mode))
		{
		openvfsfuse_log(path,"mknod",res,"mknod %s %o (block device creation)",path, mode);
		}*/
        else
            openvfsfuse_log(path, "mknod", res, "mknod %s %o", path, mode);
    }


    if (res == -1)
    {
        delete[] path;
        return -errno;
    }
    else
        lchown(path, fuse_get_context()->uid, fuse_get_context()->gid);

    delete[] path;

    return 0;
}

static int openVFSfuse_mkdir(const char *orig_path, mode_t mode)
{
    int res;
    const char *path = getRelativePath(orig_path);
    res = mkdir(path, mode);
    openvfsfuse_log(path, "mkdir", res, "mkdir %s %o", path, mode);

    if (res == -1)
    {
        delete[] path;
        return -errno;
    }
    else
        lchown(path, fuse_get_context()->uid, fuse_get_context()->gid);

    delete[] path;

    return 0;
}

static int openVFSfuse_unlink(const char *orig_path)
{
    int res;
    char *path = getRelativePath(orig_path);
    res = unlink(path);
    openvfsfuse_log(path, "unlink", res, "unlink %s", path);
    delete[] path;

    if (res == -1)
        return -errno;

    return 0;
}

static int openVFSfuse_rmdir(const char *orig_path)
{
    int res;
    char *path = getRelativePath(orig_path);
    res = rmdir(path);
    openvfsfuse_log(path, "rmdir", res, "rmdir %s", path);
    delete[] path;
    if (res == -1)
        return -errno;
    return 0;
}

static int openVFSfuse_symlink(const char *from, const char *orig_to)
{
    int res;

    const char *to = getRelativePath(orig_to);

    res = symlink(from, to);

    openvfsfuse_log(to, "symlink", res, "symlink from %s to %s", to, from);

    if (res == -1)
    {
        delete[] to;
        return -errno;
    }
    else
        lchown(to, fuse_get_context()->uid, fuse_get_context()->gid);

    delete[] to;
    return 0;
}

static int openVFSfuse_rename(const char *orig_from, const char *orig_to)
{
    int res;
    const char *from = getRelativePath(orig_from);
    const char *to = getRelativePath(orig_to);
    res = rename(from, to);
    openvfsfuse_log(from, "rename", res, "rename %s to %s", from, to);
    delete[] from;
    delete[] to;

    if (res == -1)
        return -errno;

    return 0;
}

static int openVFSfuse_link(const char *orig_from, const char *orig_to)
{
    int res;

    const char *from = getRelativePath(orig_from);
    const char *to = getRelativePath(orig_to);

    res = link(from, to);
    openvfsfuse_log(to, "link", res, "hard link from %s to %s", to, from);
    delete[] from;

    if (res == -1)
    {
        delete[] to;
        return -errno;
    }
    else
        lchown(to, fuse_get_context()->uid, fuse_get_context()->gid);

    delete[] to;

    return 0;
}

static int openVFSfuse_chmod(const char *orig_path, mode_t mode)
{
    int res;
    char *path = getRelativePath(orig_path);
    res = chmod(path, mode);
    openvfsfuse_log(path, "chmod", res, "chmod %s to %o", path, mode);
    delete[] path;

    if (res == -1)
        return -errno;

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

static int openVFSfuse_chown(const char *orig_path, uid_t uid, gid_t gid)
{
    int res;
    char *path = getRelativePath(orig_path);
    res = lchown(path, uid, gid) == -1 ? -errno : 0;

    char *username = getusername(uid);
    char *groupname = getgroupname(gid);

    if (username != NULL && groupname != NULL)
        openvfsfuse_log(path, "chown", res, "chown %s to %d:%d %s:%s", path, uid, gid, username, groupname);
    else
        openvfsfuse_log(path, "chown", res, "chown %s to %d:%d", path, uid, gid);
    delete[] path;

    return res;
}

static int openVFSfuse_truncate(const char *orig_path, off_t size)
{
    int res;

    char *path = getRelativePath(orig_path);
    res = truncate(path, size);
    openvfsfuse_log(path, "truncate", res, "truncate %s to %d bytes", path, size);
    delete[] path;

    if (res == -1)
        return -errno;

    return 0;
}

#if (FUSE_USE_VERSION == 25)
static int openVFSfuse_utime(const char *orig_path, struct utimbuf *buf)
{
    int res;

    const char *path = getRelativePath(orig_path);
    res = utime(path, buf);
    openvfsfuse_log(path, "utime", res, "utime %s", path);
    delete[] path;

    if (res == -1)
        return -errno;

    return 0;
}

#else

static int openVFSfuse_utimens(const char *orig_path, const struct timespec ts[2])
{
    int res;
    const char *path = getRelativePath(orig_path);

    res = utimensat(AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW);

    openvfsfuse_log(path, "utimens", res, "utimens %s", path);
    delete[] path;

    if (res == -1)
        return -errno;

    return 0;
}

#endif

static int openVFSfuse_open(const char *orig_path, struct fuse_file_info *fi)
{
    int res;
    const char *path = getRelativePath(orig_path);
    res = open(path, fi->flags);

    // what type of open ? read, write, or read-write ?
    if (fi->flags & O_RDONLY)
    {
        openvfsfuse_log(path, "open-readonly", res, "open readonly %s", path);
    }
    else if (fi->flags & O_WRONLY)
    {
        openvfsfuse_log(path, "open-writeonly", res, "open writeonly %s", path);
    }
    else if (fi->flags & O_RDWR)
    {
        openvfsfuse_log(path, "open-readwrite", res, "open readwrite %s", path);
    }
    else
        openvfsfuse_log(path, "open", res, "open %s", path);

    delete[] path;

    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}

static int openVFSfuse_read(const char *orig_path, char *buf, size_t size, off_t offset,
                         struct fuse_file_info *fi)
{
    int res;
    const char *path = getRelativePath(orig_path);

    openvfsfuse_log(path, "read", 0, "read %d bytes from %s at offset %d", size, path, offset);
    res = pread(fi->fh, buf, size, offset);
    if (res == -1)
    {
        res = -errno;
        openvfsfuse_log(path, "read", -1, "read %d bytes from %s at offset %d", size, path, offset);
    }
    else
    {
        openvfsfuse_log(path, "read", 0, "%d bytes read from %s at offset %d", res, path, offset);
    }
    delete[] path;
    return res;
}

static int openVFSfuse_write(const char *orig_path, const char *buf, size_t size,
                          off_t offset, struct fuse_file_info *fi)
{
    int fd;
    int res;
    const char *path = getRelativePath(orig_path);
    (void)fi;

    fd = open(path, O_WRONLY);
    if (fd == -1)
    {
        res = -errno;
        openvfsfuse_log(path, "write", -1, "write %d bytes to %s at offset %d", size, path, offset);
        delete[] path;
        return res;
    }
    else
    {
        openvfsfuse_log(path, "write", 0, "write %d bytes to %s at offset %d", size, path, offset);
    }

    res = pwrite(fd, buf, size, offset);

    if (res == -1)
        res = -errno;
    else
        openvfsfuse_log(path, "write", 0, "%d bytes written to %s at offset %d", res, path, offset);

    close(fd);
    delete[] path;

    return res;
}

static int openVFSfuse_statfs(const char *orig_path, struct statvfs *stbuf)
{
    int res;
    const char *path = getRelativePath(orig_path);
    res = statvfs(path, stbuf);
    openvfsfuse_log(path, "statfs", res, "statfs %s", path);
    delete[] path;
    if (res == -1)
        return -errno;

    return 0;
}

static int openVFSfuse_release(const char *orig_path, struct fuse_file_info *fi)
{
    (void)orig_path;
    const char *path = getRelativePath(orig_path);

    openvfsfuse_log(path, "release", 0, "release %s", path);
    delete[] path;

    close(fi->fh);
    return 0;
}

static int openVFSfuse_fsync(const char *orig_path, int isdatasync,
                          struct fuse_file_info *fi)
{
    const char *path = getRelativePath(orig_path);

    (void)orig_path;
    (void)isdatasync;
    (void)fi;
    openvfsfuse_log(path, "fsync", 0, "fsync %s", path);
    delete[] path;
    return 0;
}

int dehydrate(const char *orig_path)
{
    struct stat buf;
    openVFSfuse_getattr(orig_path, &buf);
    char fsize[30];
    int res;

    int64_t s = buf.st_size;
    sprintf(fsize, "%ld", s);
    res = openVFSfuse_setxattr(orig_path, "user.openvfs.fsize", fsize, strlen(fsize), 0);

    openvfsfuse_log(orig_path, "dehydrate truncate", res, "truncate file size");

    /* truncate the file to zero */
    res = openVFSfuse_truncate(orig_path, 0);
    openvfsfuse_log(orig_path, "dehydrate", res, "truncate file");

    if (res != 0) {
        res = 0;
    }

    /* if successful, remove the action and set the state to dehydrated */
    if (res == 0) {
        res = openVFSfuse_setxattr(orig_path, "user.openvfs.state", "dehydrated", 10, 0);
    }
    return res;

}

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int openVFSfuse_setxattr(const char *orig_path, const char *name, const char *value,
                             size_t size, int flags)
{
    const char *path = getRelativePath(orig_path);

    openvfsfuse_log(path, "setxattr", 0, "setxattr %s = %s, size = %ld flags=%d", name, value, size, flags);

    int res;
    if (strcmp(name, "user.openvfs.action") == 0 && strcmp(value, "dehydrate") == 0) {
        openvfsfuse_log(path, "setxattr", 0, "setxattr detect openvfs command %s", value);
        res = dehydrate(orig_path);
    } else {
        res = lsetxattr(path, name, value, size, flags);
        openvfsfuse_log(path, "setxattr", res, "setxattr %s %d", path, errno);
    }

    delete[] path;
    if (res == -1)
        return -errno;
    return 0;
}

static int openVFSfuse_getxattr(const char *orig_path, const char *name, char *value,
                             size_t size)
{
    const char *path = getRelativePath(orig_path);

    int res = lgetxattr(path, name, value, size);
    openvfsfuse_log(path, "getxattr", 0, "getxattr %s %s", path, name);

    delete[] path;

    if (res == -1)
        return -errno;
    return res;
}

static int openVFSfuse_listxattr(const char *orig_path, char *list, size_t size)
{
    const char *path = getRelativePath(orig_path);

    int res = llistxattr(path, list, size);
    openvfsfuse_log(path, "listxattr", 0, "listxattr %s", path);
    delete[] path;
    if (res == -1)
        return -errno;
    return res;
}

static int openVFSfuse_removexattr(const char *orig_path, const char *name)
{
    const char *path = getRelativePath(orig_path);

    int res = lremovexattr(path, name);
    openvfsfuse_log(path, "removexattr", 0, "removexattr %s %s", path, name);

    delete[] path;
    if (res == -1)
        return -errno;
    return 0;
}
#endif /* HAVE_SETXATTR */

static void usage(char *name)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "%s [-h] | [-l log-file] [-c config-file] [-f] [-p] [-e] /directory-mountpoint\n", name);
    fprintf(stderr, "Type 'man openvfsfuse' for more details\n");
    return;
}

static bool processArgs(int argc, char *argv[], openVFSfuse_Args *out)
{
    // set defaults
    out->isDaemon = true;
    out->logToSyslog = true;

    out->fuseArgc = 0;
    out->configFilename = NULL;

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

#define COMMON_OPTS "nonempty,use_ino,attr_timeout=0,entry_timeout=0,negative_timeout=0,atomic_o_trunc"

    while ((res = getopt(argc, argv, "hpfec:l:")) != -1)
    {
        switch (res)
        {
        case 'h':
            usage(argv[0]);
            return false;
        case 'f':
            out->isDaemon = false;
            out->logToSyslog = false;
            // this option was added in fuse 2.x
            PUSHARG("-f");
            defaultLogger->info("openVFSfuse not running as a daemon");
            break;
        case 'p':
            PUSHARG("-o");
            PUSHARG("allow_other,default_permissions," COMMON_OPTS);
            got_p = true;
            defaultLogger->info("openVFSfuse running as a public filesystem");
            break;
        case 'e':
            PUSHARG("-o");
            PUSHARG("nonempty");
            defaultLogger->info("Using existing directory");
            break;
        case 'c':
            out->configFilename = optarg;
            defaultLogger->info("Configuration file : %v", optarg);
            break;
        case 'l':
        {
            defaultLogger->info("openVFSfuse log file : %v, no syslog logs", optarg);
            out->logToSyslog = false;
            el::Configurations defaultConf;
            defaultConf.setToDefault();
            defaultConf.setGlobally(el::ConfigurationType::ToFile, std::string("true"));
            defaultConf.setGlobally(el::ConfigurationType::ToStandardOutput, std::string("false"));
            defaultConf.setGlobally(el::ConfigurationType::Filename, std::string(optarg));
            el::Loggers::reconfigureLogger("default", defaultConf);
            defaultLogger = el::Loggers::getLogger("default");
            break;
        }
        default:
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
        fprintf(stderr, "Missing mountpoint\n");
        usage(argv[0]);
        return false;
    }

    // If there are still extra unparsed arguments, pass them onto FUSE..
    if (optind < argc)
    {
        rAssert(out->fuseArgc < MaxFuseArgs);

        while (optind < argc)
        {
            rAssert(out->fuseArgc < MaxFuseArgs);
            out->fuseArgv[out->fuseArgc++] = argv[optind];
            ++optind;
        }
    }

    if (!isAbsolutePath(out->mountPoint))
    {
        fprintf(stderr, "You must use absolute paths "
                        "(beginning with '/') for %s\n",
                out->mountPoint);
        return false;
    }
    return true;
}

int initializeOpenVFSFuse(int argc, char *argv[])
{

    el::Configurations defaultConf;
    defaultConf.setToDefault();
    defaultConf.setGlobally(el::ConfigurationType::ToFile, std::string("false"));
    el::Loggers::reconfigureLogger("default", defaultConf);
    defaultLogger = el::Loggers::getLogger("default");

    char *input = new char[2048]; // 2ko MAX input for configuration

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
#if (FUSE_USE_VERSION == 25)
    openVFSfuse_oper.utime = openVFSfuse_utime;
#else
    openVFSfuse_oper.utimens = openVFSfuse_utimens;
    openVFSfuse_oper.flag_utime_omit_ok = 1;
#endif
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

        if (openvfsfuseArgs->logToSyslog)
        {
            dispatchAction = el::base::DispatchAction::SysLog;
            loggerId = "syslog";
        }

        defaultLogger->info("openVFSfuse starting at %v.", openvfsfuseArgs->mountPoint);

        if (openvfsfuseArgs->configFilename != NULL)
        {

            if (strcmp(openvfsfuseArgs->configFilename, "-") == 0)
            {
                defaultLogger->info("Using stdin configuration");
                memset(input, 0, 2048);
                char *ptr = input;

                int size = 0;
                do
                {
                    size = fread(ptr, 1, 1, stdin);
                    ptr++;
                } while (!feof(stdin) && size > 0);
                config.loadFromXmlBuffer(input);
            }
            else
            {
                defaultLogger->info("Using configuration file %v.", openvfsfuseArgs->configFilename);
                config.loadFromXmlFile(openvfsfuseArgs->configFilename);
            }
        }
        delete[] input;
        defaultLogger->info("chdir to %v", openvfsfuseArgs->mountPoint);
        chdir(openvfsfuseArgs->mountPoint);
        savefd = open(".", 0);

#if (FUSE_USE_VERSION == 25)
        fuse_main(openvfsfuseArgs->fuseArgc,
                  const_cast<char **>(openvfsfuseArgs->fuseArgv), &openVFSfuse_oper);
#else
        fuse_main(openvfsfuseArgs->fuseArgc,
                  const_cast<char **>(openvfsfuseArgs->fuseArgv), &openVFSfuse_oper, NULL);
#endif

        defaultLogger->info("openVFSfuse closing.");
    }
    return 0;
}
