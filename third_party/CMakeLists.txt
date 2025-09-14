# add_subdirectory(OpenSSL)
add_subdirectory(tiny-aes)

add_library(third_party INTERFACE)

target_link_libraries(third_party INTERFACE tiny-aes)
target_include_directories(third_party INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")
