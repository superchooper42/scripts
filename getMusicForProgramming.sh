#!/bin/bash
export linkblobg=$(curl https://www.musicforprogramming.net | grep -A1  'id="episodes" class="multi-column"' | grep href)
export sep='href="'
links=$(printf '%s\n' "${linkblob//$sep/$'\n'}" | cut -d '"' -f1)
for link in $links
do
    export mp3link=$(curl "https://www.musicforprogramming.net$link" | grep mp3 | cut -d '"' -f2 | head -n 1)    
    export filename=$(echo $mp3link | cut -d '/' -f 4)    
    wget $mp3link -o /tmp/$filename
done
