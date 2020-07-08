cmake_minimum_required(VERSION 3.13)
project(ZTP)

set(CMAKE_CXX_STANDARD 17)

find_package(libmongocxx REQUIRED)
find_package(libbsoncxx REQUIRED)
#find_package(libssh REQUIRED)

include_directories(${LIBMONGOCXX_INCLUDE_DIRS})
include_directories(${LIBBSONCXX_INCLUDE_DIRS})
add_definitions(-D_ELPP_THREAD_SAFE)
find_path(HIREDIS_HEADER hiredis)
include_directories(${HIREDIS_HEADER})

find_path(REDIS_PLUS_PLUS_HEADER sw)
include_directories(${REDIS_PLUS_PLUS_HEADER})



add_executable(ztp src/main.cpp src/alive_test.cpp src/alive_test.h src/config.cpp src/config.h src/os_finder_ssh.cpp
                   src/os_finder_ssh.h src/version_ops.cpp src/version_ops.h src/ssh_client.cpp
                   src/ssh_client.h src/database_ctrl.cpp src/database_ctrl.h src/data_types.h
                   src/helper.cpp src/helper.h src/vendor/easylogging++/easylogging++.cpp
                   src/vendor/easylogging++/easylogging++.h modules/local_security.cpp modules/local_security.h
                   modules/windows_local_security.cpp modules/windows_local_security.h
                   src/windows_commands.cpp src/windows_commands.h)

set_target_properties(ztp PROPERTIES CXX_STANDARD 17)

target_link_libraries(ztp ${LIBMONGOCXX_LIBRARIES})
target_link_libraries(ztp ${LIBBSONCXX_LIBRARIES})
#target_link_libraries(ztp ${LIBSSH_LIBRARIES})
target_link_libraries(ztp stdc++fs)
target_link_libraries(ztp ssh)
target_link_libraries(ztp pthread)

find_library(HIREDIS_LIB hiredis)
target_link_libraries(ztp ${HIREDIS_LIB})

find_library(REDIS_PLUS_PLUS_LIB redis++)
target_link_libraries(ztp ${REDIS_PLUS_PLUS_LIB})

install(TARGETS ztp DESTINATION /usr/local/bin)

IF (NOT EXISTS /var/log/ztp)
    file(MAKE_DIRECTORY /var/log/ztp)
ENDIF()

IF (NOT EXISTS /etc/ztp)
    file(MAKE_DIRECTORY /etc/ztp)
ENDIF()

install(FILES "${PROJECT_BINARY_DIR}/../config/ztplogging.conf" DESTINATION /etc/ztp/)

