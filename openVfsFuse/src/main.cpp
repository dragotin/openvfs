#include <cassert>
#include <filesystem>

#include "3rdparty/json.hpp"
#include "openvfsfuse.h"
#include "strtools.h"

#include <getopt.h>
#include <iostream>
#include <optional>
#include <vector>
#include <fstream>


using json = nlohmann::json;

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


namespace {
const std::string FuseStandardArgsStr = "attr_timeout=0,entry_timeout=0,negative_timeout=0";
const std::string ConfigIgnoreAppsStr = "ignoreApps";
const std::string ConfigByNameStr = "byName";
const std::string ConfigEndsWith = "endsWith";
}

void usage(char *name)
{
    std::cerr << "Usage:" << std::endl //
              << name << " [-h] | [-f] [-p] [-d] [-i config-file] /directory-mountpoint" << std::endl //
              << "Type 'man openvfsfuse' for more details" << std::endl;
}

std::optional<openVFSfuse_Args> processArgs(int argc, char *argv[])
{
    openVFSfuse_Args out;
    // pass executable name through
    out.fuseArgv.emplace_back(argv[0]);
    opterr = 0;

    int res;

    bool got_p = false;

    while ((res = getopt(argc, argv, "hpfdi:")) != -1) {
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
            out.fuseArgv.emplace_back("allow_other,default_permissions," + FuseStandardArgsStr);
            got_p = true;
            std::cout << "openVFSfuse running as a public filesystem" << std::endl;
            break;
        case 'd':
            // enable debug logging, implies -f
            out.fuseArgv.emplace_back("-d");
            std::cout << "openVFSfuse running with debug log enabled" << std::endl;
            break;
        case 'i': {
            std::ifstream ifs(optarg);
            json data = json::parse(ifs);

            out.appsNoHydrateFull = data[ConfigIgnoreAppsStr][ConfigByNameStr].get< std::vector< std::string > > ();
            out.appsNoHydrateEndsWith = data[ConfigIgnoreAppsStr][ConfigEndsWith].get< std::vector< std::string > > ();
            break;
        }
        default:
            assert(false);
            break;
        }
    }

    if (!got_p) {
        out.fuseArgv.emplace_back("-o");
        out.fuseArgv.emplace_back(FuseStandardArgsStr.c_str());
    }

    if (optind + 1 <= argc) {
        out.mountPoint = std::filesystem::canonical(argv[optind++]);
        out.fuseArgv.emplace_back(out.mountPoint);
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

    if (!out.mountPoint.is_absolute()) {
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
        return initializeOpenVFSFuse(*openvfsfuseArgs);
    }
    return -1;
}
