#/bin/bash
while true
do
    nc 127.0.0.1 8080 -z
    sleep 0.5
done
