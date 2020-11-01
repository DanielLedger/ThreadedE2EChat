## Message client
Since the whole point of an end-to-encrypted chat application is that the server cannot read messages,
the client is the one that has to do most of the work here. This document outlines the protocol the client uses.

###### Important note:
When you see SHA256(public key) or similar, only calculate the SHA256 on the public modulus (i.e. N), and ignore the exponent/e.

### Sending messages past the server
The exact details of this are on the server's desc.md, but all messages here are encoded to base64 
and sent using a SEND packet. The base64 encode is to make parsing the message by the server a lot easier.

### Keystore
There are three data storage systems used by the client:
a) A table of Username, User ID and SHA256(public key).
b) A table of User ID, HMAC salt and encrypted master secret.
c) A per-user encrypted message store: the advised way to do this is either `AES-256-CBC` or `AES-256-GCM`, depending on if authenticating stored messages is required.

The master secrets are recovered using a master password which is entered on program start using the following algorithm:

`SECRET = AES-CBC(key = HMAC-SHA256(hashed-password, salt), IV = salt, encrypted secret)`

Encrypted messages are stored in batches of about 500 - 10,000 messages (doesn't matter, ensure it's fewer than 2^64 bytes for `AES-CBC`, which is unlikely), with a unique IV for each and a key calculated as `HMAC-SHA256(hashed-password, IV)`.

The `hashed-password` should be calculated using the first method in this list that your platform can access, using paranoid-but-sensible parameters (generally look these up from no more than 2 years ago and, if unsure, double them):

##### Algorithms:
- `Argon2`
- `scrypt`
- `bcrypt`
- `pbkdf_hmac_sha256`
- `HMAC-SHA256` 

### New chat handshake
When you want to message a user you haven't messaged yet, the following data is sent.
This data is encrypted differently for different parts:
`<user-id>` is encrypted with the user's **private** key, to verify they are who they claim to be.
`<master secret>` is encrypted with the user's **public** key.

You: `INIT <user-id> <cleartext-user-id> <32 byte master secret> `

The client can then send as many messages as they wish using that master secret.

### Receiving messages
Receiving messages is as simple as parsing the INIT packet and setting this chat to use that master secret.
In addition, the sender's public key should also be downloaded and stored in keystore A (as above).

### Sending and receiving messages
The packet structure of a message is very simple:

`MSG <payload>`

Each message is encrypted using the following algorithm:

`MSG = msg_count||IV||AES-256-GCM(key = HMAC-SHA256(master_secret, 0xabcdef), iv = IV, message).data||AES-256-GCM.tag`

The IV is 16 bytes long and randomly generated, and the GCM tag is also not truncated and must be verified before displaying the message to the user. 

The msg_count is a simple counter that tracks the amount of messages sent and received.

If a message arrives with a counter that is higher than expected, the following exchange will be sent:

A: `CTR MISSING <missing message number> <missing message number> ...`

B will then send a series of packets that are either:

B: `MSG_REPLAY <counter> <payload>`
Or, if B cannot recover the sent messages:

B: `MSG REPLAY <counter> NOT FOUND`

If B has to send that packet, both clients should tell their users that a message was lost in transit.

If a message arrives with a lower than expected counter, the following packet will be sent:

A: `CTR EXCESS <A's counter value>`

This will prompt B to reply with the same exchange as if A had failed to receive any messages.

Once counter can be safely incremented, it is, and the following calculation is done:

`master_secret[ctr] = HMAC-SHA256(master_secret[ctr - 1], 0x0123456789abcdef)`

This means that, even if the master secret is somehow compromised, previously intercepted messages are still unrecoverable forever

### Rekeying
Clients should provide an option to rekey their exchanges if they believe their master secret was compromised, which triggers the following exchange. Note that the REKEY packet is encrypted in the same way an INIT packet is encrypted, using the other user's public key:

Rekeyer: `REKEY <new master secret>`

Receiver: `REKEY ACCEPT` 

If they accept the rekey, or:

Receiver: `REKEY DECLINE`

### Key verification
To make a Man-in-the-middle attack harder, an option is provided to verify that the user's public keys are the same. This should be done as follows:
1) Ask the user for a passcode. This doesn't have to be secret, it just makes somehow colliding the keys even more impossible than it was before.

2) Calculate `hMe = SHA256(my public key)` and retrieve `hOther` from the database of users.

3) Let `s1 = min(hMe, hOther)` and `s2 = max(hMe, hOther)`

4) Let `k = 0x1; o = 0x0`

5) Run the following 5,000 times: `k = HMAC_SHA256(k, SHA256(s1||passcode||s2));o = HMAC_SHA256(o, k)`. This turns o into a nigh-on impossible to reverse 32 byte stream that depends entirely on s1 and s2.

6) Calculate `n = HMAC_SHA256(o, passcode)`.

7) Split n into upper 16 and lower 16 bytes. Generate two java UUIDs using them and output those. The output will look something like this:

`n1 = b97b82a8-5e2c-4faa-82f0-99a40affcdee`

`n2 = 70555819-cf52-493a-bfaf-6748e2b823e9`
