# plugboard-proxy

It is written in Go using the Crypto library

The plugboard proxy, named 'pbproxy', adds an extra
layer of encryption to connections towards TCP services. Instead of connecting
directly to the service, clients connect to pbproxy (running on the same
server), which then relays all traffic to the actual service. Before relaying
the traffic, pbproxy *always* decrypts it using a static symmetric key. This
means that if the data of any connection towards the protected server is not
properly encrypted, then it will turn into garbage before reaching the
protected service.

Clients who want to access the protected server should proxy their traffic
through a local instance of pbroxy, which will encrypt the traffic using the
same symmetric key used by the server. In essence, pbproxy can act both as
a client-side proxy and as server-side reverse proxy, in a way similar to
netcat.

The program conforms to the following specification:

go run pbproxy.go [-l listenport] -p pwdfile destination port

-l Reverse-proxy mode: listen for inbound connections on listenport and
relay them to destination:port

-p Use the ASCII text passphrase contained in pwdfile

* In client mode, pbproxy reads plaintext traffic from stdin and transmits it
in encrypted form to destination:port

* In reverse-proxy mode, pbproxy continues listening for incoming
connections after a previous session is terminated, and it handles multiple concurrent connections (all using the same key).

* Data will be encrypted/decrypted using AES-256 in GCM mode (bi-directional
communication). An appropriate AES key is derived from the supplied passphrase using PBKDF2.
