## Packet manager
This is a utility jar to make handling networky stuff A LOT easier.

Usage is very simple: it defines one class: Connection()

### Sending packets
Sending packets can be done through the Connection#send() method. Javadocs give a full description.
Note that if you are expecting a response, the transfer method may be better for you (see below).

### Recieving packets
If you simply want to listen for packets, then Connection#onRecv() is your friend.

### Send-Recv packet
If you are sending a packet and expecting a response, then use Connection#sendRecv(). Note that to respond to a packet being sent to you
you should simply use onRecv().
