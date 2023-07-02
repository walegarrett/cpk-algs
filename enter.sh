#!/bin/bash

echo run tidy
go mod tidy
echo run build
go build -o smq -buildvcs=false .
export PATH=$PATH:`pwd`
echo run completion
source <(smq completion bash)