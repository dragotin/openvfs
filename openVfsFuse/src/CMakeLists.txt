include(ECMMarkNonGuiExecutable)

set (openVFS_SRC
	main.cpp
	openvfsfuse.cpp
	socketthread.cpp
	sharedmap.cpp
	xattr.cpp
	strtools.cpp
)

add_executable(openvfsfuse ${openVFS_SRC})
set_target_properties(openvfsfuse PROPERTIES EXPORT_NAME OpenVFS)
ecm_mark_nongui_executable(openvfsfuse)

target_include_directories(openvfsfuse PRIVATE 3rdparty)
target_link_libraries(openvfsfuse FUSE::FUSE)

# disable darwin extensions for now
target_compile_definitions(openvfsfuse PRIVATE FUSE_DARWIN_ENABLE_EXTENSIONS=0)

install(TARGETS openvfsfuse EXPORT OpenVFSConfig ${KDE_INSTALL_TARGETS_DEFAULT_ARGS} )
install(EXPORT OpenVFSConfig DESTINATION lib/cmake/openvfs NAMESPACE OpenVFS::)
