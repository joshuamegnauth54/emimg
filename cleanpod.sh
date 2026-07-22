#!/bin/sh

set -e

podman-compose down -v --rmi all
