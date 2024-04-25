cd ../
./ssikit.sh key list | awk -F" " '{print $3}' | tail -n +7 | tr -d '"' | while read -r line; do ./ssikit.sh key delete $line; done
