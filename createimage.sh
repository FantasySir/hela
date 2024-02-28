#!/bin/bash
if [ $# -ne 1 ]; then
    echo "Usage: $0 <file>"
    exit 1
fi


while IFS= read -r line; do

   
    docker pull  "$line"
    # 设置eBPF程序
    #　
    # docker run "$line"
done < "$1" 