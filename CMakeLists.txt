cmake_minimum_required(VERSION 3.16)
project(nat-dpdk C)
set(CMAKE_C_STANDARD 11)

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBYAML QUIET yaml-0.1)
if(NOT LIBYAML_FOUND)
  pkg_check_modules(LIBYAML REQUIRED yaml)
endif()
pkg_check_modules(DPDK REQUIRED libdpdk)

# add_executable(yaml_parser_test
#   src/yaml-main.c
#   src/config_yaml.c
# )

# add_executable(port_init_test
#     src/port-init-main.c
#     src/config_yaml.c
#     src/dpdk_port.c
# )

add_executable(dpdk-router-nat
  src/arp.c
  src/config_yaml.c
  src/dpdk_port.c
  src/main.c
)

# target_include_directories(yaml_parser_test PRIVATE
#   include
#   ${LIBYAML_INCLUDE_DIRS}
# )

# target_link_libraries(yaml_parser_test PRIVATE
#   ${LIBYAML_LIBRARIES}

# )

# target_compile_options(yaml_parser_test PRIVATE
#   ${LIBYAML_CFLAGS_OTHER}
# )

# target_include_directories(port_init_test PRIVATE
#   include
#   ${LIBYAML_INCLUDE_DIRS}
#   ${DPDK_INCLUDE_DIRS}
# )

# target_link_libraries(port_init_test PRIVATE
#   ${LIBYAML_LIBRARIES}
#   ${DPDK_LIBRARIES}
# )

# target_compile_options(port_init_test PRIVATE
#   ${LIBYAML_CFLAGS_OTHER}
#   ${DPDK_CFLAGS_OTHER}
# )



target_include_directories(dpdk-router-nat PRIVATE
  include
  ${LIBYAML_INCLUDE_DIRS}
  ${DPDK_INCLUDE_DIRS}
)

target_link_libraries(dpdk-router-nat PRIVATE
  ${LIBYAML_LIBRARIES}
  ${DPDK_LIBRARIES}
)

target_compile_options(dpdk-router-nat PRIVATE
  ${LIBYAML_CFLAGS_OTHER}
  ${DPDK_CFLAGS_OTHER}
)

