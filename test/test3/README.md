## TEST 3

### Objective  
Ensure the server properly handles write queuing when the client is slow or multiple writes occur rapidly.

### Instructions  
- Implement a server that rapidly writes multiple frames to the client.  
- Implement a client that makes a request and reads incoming data slowly.  
- The server should send multiple frames, and the client should verify that all are received correctly.  

### Purpose  
- Confirms that write queuing functions as expected.  
- Ensures data is not lost or sent too quickly for a slow client.
