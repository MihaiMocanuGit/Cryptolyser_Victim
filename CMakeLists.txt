cmake_minimum_required(VERSION 3.25)
project(Cryptolyser_Victim VERSION 0.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)

if (WIN32)
    FATAL_ERROR("Windows is not supported.")
endif (WIN32)

find_package(OpenSSL REQUIRED)

set(GCC_FLAGS_DEBUG "-O0 -Wall -Wextra -Wpedantic -Werror -Wno-unused-variable -Wno-unused-parameter -fsanitize=address,undefined")
set(GCC_LINK_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address,undefined")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${GCC_FLAGS_DEBUG}")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} ${GCC_LINK_FLAGS_DEBUG}")

add_subdirectory(AES)
add_subdirectory(ConnectionHandler)

add_executable(${PROJECT_NAME} main.c)

target_link_libraries(${PROJECT_NAME} PRIVATE AES ConnectionHandler OpenSSL::Crypto)
