cmake_minimum_required(VERSION 3.14.7)

project(monitor
  VERSION 0.2
  DESCRIPTION "A simple tool for monitoring jpeg streams over UDP.")

include(FetchContent)

if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

FetchContent_Declare(uikit URL "https://github.com/tay10r/uikit/archive/refs/tags/v0.1.3.zip")
FetchContent_MakeAvailable(uikit)

find_package(libuv CONFIG REQUIRED)

add_executable(monitor WIN32
  src/main.cpp
  src/stb_image.h
  src/stb_image.c
  src/stb_image_write.h
  src/stb_image_write.c)
target_link_libraries(monitor PUBLIC uikit::uikit uikit::main libuv::uv)
target_compile_features(monitor PUBLIC cxx_std_20)

install(TARGETS monitor
  DESTINATION bin)

set (CPACK_PACKAGE_CONTACT "Taylor Holberton")
set (CPACK_PACKAGE_DESCRIPTION_SUMMARY "${monitor_DESCRIPTION}")
set (CPACK_DEBIAN_PACKAGE_DEPENDS libgl1 libc6 libx11-6)

include(CPack)
