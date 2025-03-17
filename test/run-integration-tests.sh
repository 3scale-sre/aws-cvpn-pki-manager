#!/bin/bash

apt-get update && apt-get install -y curl
curl -sL https://github.com/aviaviavi/curl-runnings/releases/download/0.12.0/curl-runnings-0.12.0.tar.gz -o /tmp/curl-runnings
tar -C /bin -xvf /tmp/curl-runnings
/bin/curl-runnings -f test/integration-tests.yaml