## Threaded server.
Since the whole app is end-to-end encrypted, the server is pretty much a relay server. All it does is send and receive structured packets.
It also tracks public keys, but that is essentially it.

NOTE: Once you've registered to the server, you cannot reregister using the same name or ID. This is a security feature.

The packet structure is as follows:
`<user id> <payload>`. That's it.

### Handshake protocol
There is also an initial handshake (to verify that the user is who they say they are).
Client: `HELLO <user id>`
Server: `CHALLENGE <base64 blob>`
Client: `RESP <base64 blob>`

The CHALLENGE is a random binary token, encrypted with the public key the user shared with the server before.
The RESP is this challenge decrypted. If it is incorrect, the server will drop the connection.

### Register protocol
The registration protocol is called the first time a server is connected to.
Client: `HELLO <user id>`
Server: `NEW`
Client: `PERSON <name>`
Client: `CRYPT <public key>`

### Control packets
Some control packets will need to be exchanged for the service to work:

###### Lookup user
Client: `GET <name>`
Server: `USER <user id>`

###### Get public key
Client: `KEY <user id>`
Server: `PKEY <base64 blob>`