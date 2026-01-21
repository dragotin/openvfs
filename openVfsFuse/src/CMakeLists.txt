
set (openVFS_SRC
	main.cpp
	openvfsfuse.cpp
	socketthread.cpp
	sharedmap.cpp
	xattr.cpp
)

add_executable(openvfsfuse ${openVFS_SRC})
target_include_directories(openvfsfuse PRIVATE 3rdparty)
set_target_properties(openvfsfuse PROPERTIES EXPORT_NAME OpenVFS)

target_link_libraries(openvfsfuse FUSE::FUSE)

add_compile_definitions(ELPP_THREAD_SAFE)

install(TARGETS openvfsfuse EXPORT OpenVFSConfig ${KDE_INSTALL_TARGETS_DEFAULT_ARGS} )
install(EXPORT OpenVFSConfig DESTINATION lib/cmake/openvfs NAMESPACE OpenVFS::)
