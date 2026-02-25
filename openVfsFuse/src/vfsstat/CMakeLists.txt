add_executable(openvfs_stat main.cpp)
target_link_libraries(openvfs_stat PRIVATE openvfs)

install(TARGETS openvfs_stat ${KDE_INSTALL_TARGETS_DEFAULT_ARGS})
