cmake_minimum_required(VERSION 3.16)
project(nat-dpdk C)
set(CMAKE_C_STANDARD 11)

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBYAML QUIET yaml-0.1)
if(NOT LIBYAML_FOUND)
  pkg_check_modules(LIBYAML REQUIRED yaml)
endif()

add_executable(yaml_parser_test
  src/yaml-main.c
  src/config_yaml.c
)

target_include_directories(yaml_parser_test PRIVATE
  include
  ${LIBYAML_INCLUDE_DIRS}
)

target_link_libraries(yaml_parser_test PRIVATE
  ${LIBYAML_LIBRARIES}
)

target_compile_options(yaml_parser_test PRIVATE
  ${LIBYAML_CFLAGS_OTHER}
)
