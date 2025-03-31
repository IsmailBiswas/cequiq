add_test(NAME TestServerOnline COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test1.sh)
add_test(NAME TestDataTransfer COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test2.sh)
add_test(NAME TestWriteQueueForSlowClient COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test3.sh)

add_subdirectory(test1)
add_subdirectory(test2)
add_subdirectory(test3)
