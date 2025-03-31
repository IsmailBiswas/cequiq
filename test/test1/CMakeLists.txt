add_executable(test1_server server.c)
add_executable(test1_client client.c)
target_link_libraries(test1_server cequiq)
target_link_libraries(test1_client OpenSSL::SSL OpenSSL::Crypto)
