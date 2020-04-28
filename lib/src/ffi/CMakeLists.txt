cmake_minimum_required(VERSION 3.7 FATAL_ERROR)
project(ed25519_blake2b VERSION 1.0.0 LANGUAGES C)

if(APPLE)
    set(OPENSSL_ROOT_DIR /usr/local/opt/openssl/)
    set(OPENSSL_LIBRARIES /usr/local/opt/openssl/lib)
endif(APPLE)

find_package(openssl REQUIRED)

add_library(ed25519_blake2b SHARED ed25519_blake2b.c)

file(GLOB Blake2b_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/blake2b/*.c)
file(GLOB Blake2b_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/blake2b/*.h) 

add_library(blake2b SHARED ${Blake2b_SOURCES} ${Blake2b_HEADER})

file(GLOB Ed25519_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/ed25519-donna/*.c)
file(GLOB Ed25519_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/ed25519-donna/*.h) 

add_library(ed25519-donna ${Ed25519_SOURCES} ${Ed25519_HEADER})

target_link_libraries(ed25519_blake2b blake2b)

set_target_properties(ed25519_blake2b PROPERTIES
    PUBLIC_HEADER ed25519_blake2b.h
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    OUTPUT_NAME "ed25519_blake2b"
    XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "Hex_Identity_ID_Goes_Here"
)