#!/bin/bash
# docker-compose -f docker-compose.server.yaml up
# docker-compose -f docker-compose.client.yaml up

docker compose -f docker-compose.yaml up
# sudo docker run -i -t --entrypoint /bin/bash zkp-protocol-ex_protocolserver

# docker rmi -f $(docker images -aq)