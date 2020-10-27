## Threaded server.
Since the whole app is end-to-end encrypted, the server is pretty much a relay server. All it does is send and receive structured packets.
It also tracks public keys, but that is essentially it.

NOTE: Once you've registered to the server, you cannot reregister using the same name or ID. This is a security feature.


### Handshake protocol
There is an initial handshake (to verify that the user is who they say they are).
Client: `HELLO <user id>`
Server: `CHALLENGE <base64 blob>`

The CHALLENGE is a random binary token, encrypted with the public key the user shared with the server before.
The user's token for requests where it is required is then calculated as follows:
`HMAC-SHA256(challenge-token || SHA256(message), packet-num);`
In addition, <packet num> must be strictly greater than the number on the last successfully received message (to prevent replay attacks).
This way, every single message has multiple layers of authentication baked into it (both through the token and also any other methods like AES-GCM).

### Register protocol
The registration protocol is called the first time a server is connected to.
Client: `HELLO <user id>`
Server: `NEW`
Client: `PERSON <name>`
Client: `CRYPT <public key>`

### Control packets
Some control packets will need to be exchanged for the service to work:

###### Lookup user
Client: `GET <name> <packet num> <token> <user id>`
Server: `USER <user id>`

OR:

Client: `GETID <user id> <packet num> <token> <user id>`
Server: `USER <name>`

###### Get public key
Client: `KEY <user id> <packet num> <token> <user id>`
Server: `PKEY <base64 blob>`

###### Check for messages (cryptography control and normal)
Client: `MESSAGES <packet num> <token> <user id>`
Server: `LENGTH <incoming blob length>`
Server: `MSG <payload>; MSG <payload>;...`

###### Send message to user (cryptography control and normal)
Client: `SEND <payload> <target-user-id> <packet num> <token> <user id>`