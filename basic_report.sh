#!/bin/bash
#
# Description: Creates a CSV containing information about online files (filetype and hashes).
# Usage:       bash basic_report.sh INPUTFILE OUTPUTFILE
#

INPUT="$1"
OUTPUT="$2"

# Get analysis time
NLCOUNT=$(wc -l $INPUT | awk '{print $1}')
URLCOUNT=$(echo "$NLCOUNT + 1" | bc -l)
echo "Attempting to download $URLCOUNT files. Hang tight..."

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
    OBFURL=$(echo "$URL" | sed -e 's/http/hxxp/gi' -e 's/\./[.]/g' )
    RESOURCE=$(echo "$URL" | cut -d / -f 4- | sed 's/^/\//g')
    FILEOUTPUT=$(file --mime-type downloadedFile)
    FILETYPE=${FILEOUTPUT#downloadedFile: *}
    if [[ ! -f downloadedFile ]]
    then
        echo "$OBFURL,$RESOURCE,,,,file not found" >> "$OUTPUT"
        continue
    fi    
    MD5=$(md5sum downloadedFile | awk '{print $1}')
    SHA256=$(sha256sum downloadedFile | awk '{print $1}')
    rm -f downloadedFile
    echo "$OBFURL,$RESOURCE,$FILETYPE,$MD5,$SHA256,download" >> "$OUTPUT"
done<sorted_input.txt

# Remove sorted input file
rm -f sorted_input.txt
