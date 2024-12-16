cmake_minimum_required(VERSION 3.29)
project(Cryptolyser_Victim C)

set(CMAKE_C_STANDARD 11)

set(GCC_FLAGS_DEBUG "-O0 -Wall -Wextra -Wpedantic -Wno-unused-variable -Wno-unused-parameter -fsanitize=address,undefined")
set(GCC_LINK_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address,undefined")
set(GCC_LINK_LIBS_DEBUG "-lcrypto")

if (MSVC)
    message( FATAL_ERROR "MSVC is not (yet) supported." )
else()
    set(CMAKE_CXX_FLAGS_DEBUG "${GCC_FLAGS_DEBUG}")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${GCC_LINK_FLAGS_DEBUG} ${GCC_LINK_LIBS_DEBUG}")
endif()

add_subdirectory(AES)

add_executable(Cryptolyser_Victim main.c)

target_link_libraries(Cryptolyser_Victim PRIVATE AES)
