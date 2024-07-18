cd ../
./ssikit.sh did list | awk -F" " '{print $3}' | tail -n +7 | while read -r line; do ./ssikit.sh did delete -d "$line"; done
