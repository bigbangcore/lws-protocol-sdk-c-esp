# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.12)

#include(./cmake/ClangFormat.cmake REQUIRED)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

add_compile_options(-DCONFIG_IDF_TARGET_ESP8266)

project(lws-iot-esp)

FILE(GLOB_RECURSE ALL_C_SOURCES 
    "./main/src/*.c" 
    "./components/*/src/*.c" 
)

FILE(GLOB_RECURSE ALL_CPP_SOURCES 
    "./main/src/*.cpp" 
    "./components/*/src/*.cpp" 
)

FILE(GLOB_RECURSE ALL_HEADERS
    "./main/include/*.h" 
    "./main/include/*.hpp" 
    "./components/*/include/*.h" 
    "./components/*/include/*.hpp" 
)

#clangformat_setup(${ALL_C_SOURCES} ${ALL_CPP_SOURCES} ${ALL_HEADERS})