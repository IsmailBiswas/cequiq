add_executable(test3_server server.c)
add_executable(test3_client client.c)
target_link_libraries(test3_server cequiq)
target_link_libraries(test3_client OpenSSL::SSL OpenSSL::Crypto)
