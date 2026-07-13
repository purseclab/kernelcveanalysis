#!/bin/sh

if [ -z "$1" ]
then
HOST=neil_cuttlefish
else
HOST="$1"
fi

ssh -L localhost:5037:localhost:5037 "$HOST"
