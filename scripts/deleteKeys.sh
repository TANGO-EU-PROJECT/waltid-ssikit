./ssikit.sh key list | grep -oP '"\K[^"]+' | while read -r id ; do
    ./ssikit.sh key delete "$id"
done


