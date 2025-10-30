#!/bin/sh

cd "$(dirname $0)"

python generate_java_byte_chunks.py $1 ../app/src/main/java/com/example/leakvalue/ExploitPayload.java 8192 ExploitPayload com.example.leakvalue
python generate_java_byte_chunks.py runner.jar ../app/src/main/java/com/example/leakvalue/RunnerPayload.java 8192 RunnerPayload com.example.leakvalue
