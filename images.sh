#!/bin/bash
docker compose -f docker-compose.yaml up


# sudo docker run -i -t --entrypoint /bin/bash protocolserver
# docker rmi -f $(docker images -aq)