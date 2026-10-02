# Technical uses that are allowed inside the egress harness

Create a sealed bridge with `docker network create --internal ever-audit`.
The sniffer shares the product's network namespace through `network_mode: service:api`
and needs `cap_add: [NET_RAW, NET_ADMIN]` for the network capture.
A refused connection is logged as a network error.
