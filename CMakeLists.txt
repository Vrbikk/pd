cmake_minimum_required(VERSION 3.8)
project(pd)

set(CMAKE_C_STANDARD 11)
set(SOURCE_FILES main.c ndpi_util.h ndpi_util.c uthash.h config.h logger.c logger.h db.c db.h)
find_package( Threads )

add_executable(pd ${SOURCE_FILES})

ADD_LIBRARY(ndpi STATIC IMPORTED)
SET_TARGET_PROPERTIES(ndpi PROPERTIES IMPORTED_LOCATION /usr/local/lib/libndpi.a)

ADD_LIBRARY(pcap STATIC IMPORTED)
SET_TARGET_PROPERTIES(pcap PROPERTIES IMPORTED_LOCATION /usr/local/lib/libpcap.so)

ADD_LIBRARY(mysql STATIC IMPORTED)
SET_TARGET_PROPERTIES(mysql PROPERTIES IMPORTED_LOCATION /usr/lib/x86_64-linux-gnu/libmariadbclient.so)

target_link_libraries(pd ndpi pcap mysql ${CMAKE_THREAD_LIBS_INIT})
