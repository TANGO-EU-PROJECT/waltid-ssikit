./ssikit.sh did list | grep -oP 'did:[a-z]+:[a-zA-Z0-9:.-]+' | while read -r line ; do
    ./ssikit.sh did delete -d "$line"
done

./ssikit.sh did list | sed 's/.*: //' | while read -r id ; do
    ./ssikit.sh did delete -d "$id"
done
