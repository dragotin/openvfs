include(ECMMarkNonGuiExecutable)

add_subdirectory(vfsstat)



add_library(openvfsfuse_lib STATIC
		openvfsfuse.cpp
		socketthread.cpp
		sharedmap.cpp
		xattr.cpp
		strtools.cpp
)
target_link_libraries(openvfsfuse_lib PRIVATE FUSE::FUSE nlohmann_json::nlohmann_json)

add_executable(openvfsfuse main.cpp)
target_link_libraries(openvfsfuse PRIVATE openvfsfuse_lib)
set_target_properties(openvfsfuse PROPERTIES EXPORT_NAME OpenVFS)
ecm_mark_nongui_executable(openvfsfuse)


# disable darwin extensions for now
target_compile_definitions(openvfsfuse PRIVATE FUSE_DARWIN_ENABLE_EXTENSIONS=0)

install(TARGETS openvfsfuse EXPORT OpenVFSConfig ${KDE_INSTALL_TARGETS_DEFAULT_ARGS} )
install(EXPORT OpenVFSConfig DESTINATION ${KDE_INSTALL_CMAKEPACKAGEDIR}/openvfs NAMESPACE OpenVFS::)
install(FILES config.json DESTINATION ${KDE_INSTALL_CONFDIR}/openvfs)
install(FILES openvfconstants.h openvfsattributes.h DESTINATION ${KDE_INSTALL_INCLUDEDIR}/openvfs)
