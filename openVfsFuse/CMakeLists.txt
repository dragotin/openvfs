cmake_minimum_required(VERSION 3.16)

project(openVfsFuse LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FeatureSummary)
feature_summary(WHAT REQUIRED_PACKAGES_NOT_FOUND FATAL_ON_MISSING_REQUIRED_PACKAGES)

find_package(ECM 6.0.0 REQUIRED NO_MODULE)
set_package_properties(ECM PROPERTIES TYPE REQUIRED DESCRIPTION "Extra CMake Modules." URL "https://projects.kde.org/projects/kdesupport/extra-cmake-modules")
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ ${ECM_MODULE_PATH} ${CMAKE_MODULE_PATH})

include(KDEInstallDirs)
include(KDECMakeSettings)

include(KDECompilerSettings NO_POLICY_SCOPE)
include(KDEGitCommitHooks)

# Qt does not support exceptions therefor KDE disables them by default
kde_enable_exceptions()

# enable clang format git hook
kde_configure_git_pre_commit_hook(CHECKS CLANG_FORMAT)

add_compile_definitions(_FILE_OFFSET_BITS=64)
add_compile_definitions(FUSE_USE_VERSION=30)

find_package(fuse REQUIRED)

add_subdirectory(src)


feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
