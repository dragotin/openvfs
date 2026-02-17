add_executable(openvfs_stat main.cpp)
target_link_libraries(openvfs_stat PRIVATE openvfsfuse_lib nlohmann_json::nlohmann_json)

install(TARGETS openvfs_stat ${KDE_INSTALL_TARGETS_DEFAULT_ARGS})
