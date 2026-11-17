cmake_minimum_required(VERSION 3.16)
project(WeightedGG18 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(MultiPartySig REQUIRED)
find_package(SafeheronCryptoSuites REQUIRED)
find_package(Protobuf REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
add_executable(gg18_party gg18_party.cpp)
target_link_libraries(gg18_party PRIVATE MultiPartySig SafeheronCryptoSuites
    protobuf::libprotobuf OpenSSL::Crypto Threads::Threads)
target_compile_options(gg18_party PRIVATE -Wall -Wextra)
# Upstream exported targets may not propagate their installed header directories.
target_include_directories(gg18_party PRIVATE ${MultiPartySig_INCLUDE_DIRS}
    ${SafeheronCryptoSuites_INCLUDE_DIRS})

add_executable(gg18_virtual_bench virtual_bench.cpp)
target_link_libraries(gg18_virtual_bench PRIVATE MultiPartySig SafeheronCryptoSuites
    protobuf::libprotobuf OpenSSL::Crypto Threads::Threads)
target_compile_options(gg18_virtual_bench PRIVATE -Wall -Wextra)
target_include_directories(gg18_virtual_bench PRIVATE ${MultiPartySig_INCLUDE_DIRS}
    ${SafeheronCryptoSuites_INCLUDE_DIRS})
