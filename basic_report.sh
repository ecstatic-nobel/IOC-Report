#!/bin/bash
#
# Description: Creates a CSV containing information about online files (filetype and hashes).
# Usage:       bash basic_report.sh INPUTFILE OUTPUTFILE
#

INPUT="$1"
OUTPUT="$2"

# Sort input file
sed -e 's/hxxp/http/gi' \
    -e 's/ .*//gi' \
    -e 's/ //gi' \
    -e 's/\[.\]/./g' \
    -e 's/\[d\]/./gi' \
    -e 's/\\././g' "$INPUT" | sort -u > sorted_input.txt

# Set headers
HEADERS='url,resource,fileType,md5,sha256,source'
echo "$HEADERS" > "$OUTPUT"

# Write results to output file
while read -r URL
do
    rm -f downloadedFile
    curl -s "$URL" -o downloadedFile
    RESOURCE=$(echo "$URL" | cut -d / -f 4- | sed 's/^/\//g')
    FILEOUTPUT=$(file --mime-type downloadedFile)
    FILETYPE=${FILEOUTPUT#downloadedFile: *}
    if [[ ! -f downloadedFile ]]
    then
        echo "$URL,,," >> "$OUTPUT"
        continue
    fi    
    MD5=$(md5sum downloadedFile | awk '{print $1}')
    SHA256=$(sha256sum downloadedFile | awk '{print $1}')
    rm -f downloadedFile
    echo "$URL,$RESOURCE,$FILETYPE,$MD5,$SHA256,url" >> "$OUTPUT"
done<sorted_input.txt

# Remove sorted input file
rm -f sorted_input.txt
