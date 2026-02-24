include(ECMMarkNonGuiExecutable)

add_subdirectory(vfsstat)

add_library(openvfs SHARED
		xattr.cpp
		openvfsattributes.cpp
)
target_link_libraries(openvfs PRIVATE $<BUILD_INTERFACE:nlohmann_json::nlohmann_json>)
set_target_properties(openvfs PROPERTIES EXPORT_NAME LibOpenVFS)
generate_export_header(openvfs
		EXPORT_MACRO_NAME OPENVFS_EXPORT
		EXPORT_FILE_NAME openvfs_export.h
)

add_executable(openvfsfuse
		main.cpp
		openvfsfuse.cpp
		socketthread.cpp
		sharedmap.cpp

		strtools.cpp
)
set_target_properties(openvfsfuse PROPERTIES EXPORT_NAME OpenVFS)
ecm_mark_nongui_executable(openvfsfuse)
target_link_libraries(openvfsfuse PRIVATE openvfs nlohmann_json::nlohmann_json FUSE::FUSE Threads::Threads)


# disable darwin extensions for now
target_compile_definitions(openvfsfuse PRIVATE FUSE_DARWIN_ENABLE_EXTENSIONS=0)

install(TARGETS openvfs openvfsfuse EXPORT OpenVFSConfig ${KDE_INSTALL_TARGETS_DEFAULT_ARGS} )
install(EXPORT OpenVFSConfig DESTINATION ${KDE_INSTALL_CMAKEPACKAGEDIR}/openvfs NAMESPACE OpenVFS::)
install(FILES config.json DESTINATION ${KDE_INSTALL_CONFDIR}/openvfs)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/openvfs_export.h openvfconstants.h openvfsattributes.h DESTINATION ${KDE_INSTALL_INCLUDEDIR}/openvfs)
