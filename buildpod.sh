#!/bin/sh

set -e

podman-compose up -d
exec podman-compose exec builder bash
