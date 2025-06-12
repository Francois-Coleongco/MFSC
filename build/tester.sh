#!/bin/env bash

tests=$(ls ../tests/*.test)

fifo=$(mktemp -u)
mkfifo "$fifo"

echo "starting server"
valgrind --leak-check=full ./server < "$fifo" 2> ./valgrind_out/"general.memtest" & server_pid=$!

exec 3>"$fifo"

sleep 2

cd client_fs
client_pid=-1
for test_input in $tests; do
    echo "starting client"
    cat ../$test_input
    ./client < ../$test_input & client_pid=$!
done

wait $client_pid

echo "q" >&3
exec 3>&-
rm "$fifo"
wait $server_pid;
