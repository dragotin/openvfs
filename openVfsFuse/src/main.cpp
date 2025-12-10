#include <cassert>
#include <filesystem>

#include "openvfsfuse.h"

#include <getopt.h>
#include <iostream>
#include <optional>
#include <vector>

namespace {
constexpr int MaxFuseArgs = 32;


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

std::string fuseStandardArgs = "attr_timeout=0,entry_timeout=0,negative_timeout=0";

struct openVFSfuse_Args
{
    std::string mountPoint; // where the users read files
    bool isDaemon = true; // true == spawn in background
    std::vector<std::string> fuseArgv;
};

void usage(char *name)
{
    std::cerr << "Usage:" << std::endl //
              << name << " [-h] | [-f] [-p] [-e] /directory-mountpoint" << std::endl //
              << "Type 'man openvfsfuse' for more details" << std::endl;
}

std::optional<openVFSfuse_Args> processArgs(int argc, char *argv[])
{
    openVFSfuse_Args out;
    // pass executable name through
    out.fuseArgv.emplace_back(argv[0]);

    // leave a space for mount point, as FUSE expects the mount point before
    // any flags
    out.fuseArgv.emplace_back();
    opterr = 0;

    int res;

    bool got_p = false;

    while ((res = getopt(argc, argv, "hpfe:")) != -1) {
        switch (res) {
        case 'h':
            usage(argv[0]);
            return {};
        case 'f':
            out.isDaemon = false;
            // this option was added in fuse 2.x
            out.fuseArgv.emplace_back("-f");
            std::cout << "openVFSfuse not running as a daemon" << std::endl;
            break;
        case 'p':
            out.fuseArgv.emplace_back("-o");
            out.fuseArgv.emplace_back("allow_other,default_permissions," + fuseStandardArgs);
            got_p = true;
            std::cout << "openVFSfuse running as a public filesystem" << std::endl;
            break;
        case 'e':
            out.fuseArgv.emplace_back("-o");
            out.fuseArgv.emplace_back("nonempty");
            std::cout << "Using existing directory" << std::endl;
            break;
        default:
            assert(false);
            break;
        }
    }

    if (!got_p) {
        out.fuseArgv.emplace_back("-o");
        out.fuseArgv.emplace_back(fuseStandardArgs.c_str());
    }

    if (optind + 1 <= argc) {
        out.mountPoint = argv[optind++];
        out.fuseArgv[1] = out.mountPoint.c_str();
    } else {
        std::cerr << "Missing mountpoint" << std::endl;
        usage(argv[0]);
        return {};
    }

    // If there are still extra unparsed arguments, pass them onto FUSE..
    if (optind < argc) {
        assert(out.fuseArgv.size() < MaxFuseArgs);

        while (optind < argc) {
            assert(out.fuseArgv.size() < MaxFuseArgs);
            out.fuseArgv.emplace_back(argv[optind]);
            ++optind;
        }
    }

    if (!std::filesystem::path(out.mountPoint).is_absolute()) {
        std::cerr << "You must use absolute paths (beginning with '/') for " << out.mountPoint << std::endl;
        return {};
    }

    return out;
}
}

int main(int argc, char *argv[])
{
    if (auto openvfsfuseArgs = processArgs(argc, argv)) {
        std::cout << "openVFSfuse starting at" << openvfsfuseArgs->mountPoint << "." << std::endl;
        return initializeOpenVFSFuse(openvfsfuseArgs->mountPoint, openvfsfuseArgs->fuseArgv);
    }
    return -1;
}
