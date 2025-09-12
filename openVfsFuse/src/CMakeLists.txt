set (openVFS_SRC
	main.cpp
	openvfsfuse.cpp
	Config.cpp
	Filter.cpp

	/usr/include/easylogging++.cc)

add_executable(openvfsfuse ${openVFS_SRC})
target_include_directories(openvfsfuse PRIVATE 3rdparty)

target_link_libraries(openvfsfuse ${FUSE_LIBRARIES} LibXml2::LibXml2 ${PCRE2_LIBRARIES})

install(TARGETS openvfsfuse
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

