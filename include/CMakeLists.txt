include(ExternalProject)

#TODO: Move this to a config file.
set(OPENSSL_VER OpenSSL_1_1_0-stable)
#set(OPENSSL_VER openssl-3.0.0)
#set(OPENSSL_VER openssl-3.1.0)
#set(OPENSSL_VER openssl-3.2.0)
#set(OPENSSL_VER openssl-3.4.0)
#TODO: Create a boolean in the config: IS_STATIC_LIB and construct the suffix appropriately.
set(OPENSSL_LIBRARY_SUFFIX "a")
set(OPENSSL_FORCE_REBUILD FALSE)

set(OPENSSL_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/${OPENSSL_VER}/openssl-src)
set(OPENSSL_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/${OPENSSL_VER}/openssl)
set(OPENSSL_INCLUDE_DIR ${OPENSSL_INSTALL_DIR}/include)
set(OPENSSL_CONFIGURE_COMMAND ${OPENSSL_SOURCE_DIR}/config)
set(OPENSSL_LIB_DIR_NAME lib)

set(OPENSSL_LIBSSL ${OPENSSL_INSTALL_DIR}/${OPENSSL_LIB_DIR_NAME}/libssl.${OPENSSL_LIBRARY_SUFFIX})
set(OPENSSL_LIBCRYPTO ${OPENSSL_INSTALL_DIR}/${OPENSSL_LIB_DIR_NAME}/libcrypto.${OPENSSL_LIBRARY_SUFFIX})

# Normally, CMake should rebuild the external project only if there's an upstream change detected. Unfortunately, in
# this context it's not able to detect changes (unknown reasons) and it clones and rebuilds the project every time.
#
# The only way I was able to discourage this behaviour was by checking if the library build directory is present.
# If it's present, then the ExternalProject_Add() will not be called, and cmake will instead link directly to this
# directory.
if (NOT OPENSSL_FORCE_REBUILD AND EXISTS ${OPENSSL_INCLUDE_DIR}/openssl)
    message(STATUS "The desired openssl appears to be present in: ${OPENSSL_INCLUDE_DIR}. Skipping rebuild...")

    add_library(OpenSSL::SSL STATIC IMPORTED GLOBAL)
    set_property(TARGET OpenSSL::SSL PROPERTY IMPORTED_LOCATION ${OPENSSL_LIBSSL})
    set_property(TARGET OpenSSL::SSL PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})

    add_library(OpenSSL::Crypto STATIC IMPORTED GLOBAL)
    set_property(TARGET OpenSSL::Crypto PROPERTY IMPORTED_LOCATION ${OPENSSL_LIBCRYPTO})
    set_property(TARGET OpenSSL::Crypto PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
else ()
    # I cannot find out how to move this OpenSSL-prefix into ${CMAKE_CURRENT_BINARY_DIR}/${OPENSSL_VER}/.
    # As a workaround, it will be deleted when a different version of openssl is needed
    file(REMOVE_RECURSE ${CMAKE_CURRENT_BINARY_DIR}/OpenSSL-prefix)

    ExternalProject_Add(
            OpenSSL
            SOURCE_DIR ${OPENSSL_SOURCE_DIR}
            GIT_REPOSITORY https://github.com/openssl/openssl.git
            GIT_TAG ${OPENSSL_VER}
            BUILD_ALWAYS TRUE
            GIT_PROGRESS TRUE
            GIT_SHALLOW TRUE
            USES_TERMINAL_DOWNLOAD TRUE
            CONFIGURE_COMMAND
            ${OPENSSL_CONFIGURE_COMMAND}
            --prefix=${OPENSSL_INSTALL_DIR}
            --openssldir=${OPENSSL_INSTALL_DIR}
            --libdir=${OPENSSL_LIB_DIR_NAME}
            BUILD_COMMAND make
            TEST_COMMAND ""
            INSTALL_COMMAND make install
            INSTALL_DIR ${OPENSSL_INSTALL_DIR}
            LOG_DIR ${CMAKE_CURRENT_BINARY_DIR}/${OPENSSL_VER}/logs
            LOG_CONFIGURE ON
            LOG_BUILD ON
            LOG_INSTALL ON
            #needed by ninja, see: https://stackoverflow.com/questions/54866067/cmake-and-ninja-missing-and-no-known-rule-to-make-it
            BUILD_BYPRODUCTS ${OPENSSL_LIBCRYPTO}
    )
    # We cannot use find_library because ExternalProject_Add() is performed at build time. And to please the property
    # INTERFACE_INCLUDE_DIRECTORIES, we make the include directory in advance.
    file(MAKE_DIRECTORY ${OPENSSL_INCLUDE_DIR})

    add_library(OpenSSL::SSL STATIC IMPORTED GLOBAL)
    set_property(TARGET OpenSSL::SSL PROPERTY IMPORTED_LOCATION ${OPENSSL_LIBSSL}})
    set_property(TARGET OpenSSL::SSL PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
    add_dependencies(OpenSSL::SSL OpenSSL)

    add_library(OpenSSL::Crypto STATIC IMPORTED GLOBAL)
    set_property(TARGET OpenSSL::Crypto PROPERTY IMPORTED_LOCATION ${OPENSSL_LIBCRYPTO})
    set_property(TARGET OpenSSL::Crypto PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
    add_dependencies(OpenSSL::Crypto OpenSSL)
endif ()
