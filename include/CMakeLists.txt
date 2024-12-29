include(ExternalProject)

#TODO: Move this to a config file.
set(OPENSSL_VER OpenSSL_1_1_0-stable)
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

if (NOT OPENSSL_FORCE_REBUILD AND EXISTS ${OPENSSL_INCLUDE_DIR}/openssl)
    message(STATUS "Exists and is not an empty directory: ${OPENSSL_INCLUDE_DIR}. Skipping rebuild...")

    add_library(OpenSSL::SSL STATIC IMPORTED GLOBAL)
    set_property(TARGET OpenSSL::SSL PROPERTY IMPORTED_LOCATION ${OPENSSL_LIBSSL})
    set_property(TARGET OpenSSL::SSL PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})

    add_library(OpenSSL::Crypto STATIC IMPORTED GLOBAL)
    set_property(TARGET OpenSSL::Crypto PROPERTY IMPORTED_LOCATION ${OPENSSL_LIBCRYPTO})
    set_property(TARGET OpenSSL::Crypto PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
else ()
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
            LOG_DIR ${CMAKE_CURRENT_BINARY_DIR}/logs
            LOG_CONFIGURE ON
            LOG_BUILD ON
            LOG_INSTALL ON
            #needed by ninja, see: https://stackoverflow.com/questions/54866067/cmake-and-ninja-missing-and-no-known-rule-to-make-it
            BUILD_BYPRODUCTS ${OPENSSL_LIBCRYPTO}
    )
    # We cannot use find_library because ExternalProject_Add() is performed at build time.
    # And to please the property INTERFACE_INCLUDE_DIRECTORIES,
    # we make the include directory in advance.
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
