add_executable(test2_server server.c)
add_executable(test2_client client.c)
target_link_libraries(test2_server cequiq)
target_link_libraries(test2_client OpenSSL::SSL OpenSSL::Crypto)
