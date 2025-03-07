add_library(AES STATIC aes_interface.h aes_openssl.c)
target_link_libraries(AES PRIVATE OpenSSL::Crypto)
