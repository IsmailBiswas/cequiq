cmake_minimum_required(VERSION 3.20)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options(-Wall -Wextra -Wunused-function)

option(ENABLE_TESTING "Enable unit tests" OFF)

option(ENABLE_LOGGING "Enable debug logging" OFF)
if(ENABLE_LOGGING)
  add_definitions(-DDEBUG)
endif()

# Project name and language
project(cequiq LANGUAGES C)
# enable_testing()

# Set the version of the library
set(CEQUIQ_VERSION_MAJOR 0)
set(CEQUIQ_VERSION_MINOR 1)
set(CEQUIQ_VERSION_PATCH 0)
set(CEQUIQ_VERSION "${CEQUIQ_VERSION_MAJOR}.${CEQUIQ_VERSION_MINOR}.${CEQUIQ_VERSION_PATCH}")

# Specify the output directories for libraries and binaries
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# set(INCLUDE_DIR ./src/private_include)

find_package(OpenSSL REQUIRED)

set(SRC_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cequiq_entry.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/fd_association.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cequiq_ssl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tcp_ssl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/buffer.c
)

add_library(cequiq STATIC ${SRC_FILES})

target_include_directories(cequiq PUBLIC 
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>

  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/private_include
    
)

target_link_libraries(cequiq PRIVATE OpenSSL::SSL OpenSSL::Crypto uuid)

# Set the version for the library
set_target_properties(cequiq PROPERTIES VERSION ${CEQUIQ_VERSION} SOVERSION ${CEQUIQ_VERSION_MAJOR})

# Create a CMake package configuration for easier inclusion in other projects
install(TARGETS cequiq
        EXPORT cequiqTargets
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin)

install(DIRECTORY include/ DESTINATION include)

# Export the library for use by other projects
install(EXPORT cequiqTargets
        FILE cequiqConfig.cmake
        NAMESPACE cequiq::
        DESTINATION lib/cmake/cequiq)

if(ENABLE_TESTING)
  enable_testing()
  add_subdirectory(test)
endif()

# add_subdirectory(test)
