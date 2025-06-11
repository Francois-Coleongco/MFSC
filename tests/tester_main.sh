#!/bin/env bash

for test_input in *.test; do
    fifo=$(mktemp -u)
    mkfifo "$fifo"
    echo "starting server"
    valgrind --leak-check=full ../build/server < "$fifo" 2> ./valgrind_out/"${test_input}.memtest" & server_pid=$!
    exec 3>"$fifo"
    sleep 2
    echo "stgarting client"
    ../build/client_fs/client < $test_input 2> client_cerr_out > client_out
    echo "ending client"
    echo "q" >&3
    exec 3>&-
    rm "$fifo"
done
