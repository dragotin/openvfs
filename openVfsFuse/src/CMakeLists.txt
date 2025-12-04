
set (openVFS_SRC
	main.cpp
	openvfsfuse.cpp
	Config.cpp
	Filter.cpp
	socketthread.cpp
	Fault.cpp
	sharedmap.cpp

	/usr/include/easylogging++.cc)

add_executable(openvfsfuse ${openVFS_SRC})
target_include_directories(openvfsfuse PRIVATE 3rdparty)

target_link_libraries(openvfsfuse FUSE::FUSE LibXml2::LibXml2 ${PCRE2_LIBRARIES})

add_compile_definitions(ELPP_THREAD_SAFE)

install(TARGETS openvfsfuse
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
