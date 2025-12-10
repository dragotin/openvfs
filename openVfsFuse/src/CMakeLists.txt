
set (openVFS_SRC
	main.cpp
	openvfsfuse.cpp
	socketthread.cpp
	sharedmap.cpp
)

add_executable(openvfsfuse ${openVFS_SRC})
target_include_directories(openvfsfuse PRIVATE 3rdparty)

target_link_libraries(openvfsfuse FUSE::FUSE)

add_compile_definitions(ELPP_THREAD_SAFE)

install(TARGETS openvfsfuse
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
