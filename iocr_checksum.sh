#!/bin/bash
#
# Description: Creates a CSV containing information about online files (filetype 
#              and hashes).
# Usage:       bash basic_report.sh INPUTFILE OUTPUTFILE
#

function line_count {
    local INPUT="$1"
    wc -l $INPUT | awk '{print $1}'
}

function url_count {
    local LINECOUNT="$1"
    echo "$LINECOUNT + 1" | bc -l
}

function sort_urls {
    local INPUT="$1"
    sed -e 's/hxxp/http/gi' \
        -e 's/ .*//gi' \
        -e 's/ //gi' \
        -e 's/\[.\]/./g' \
        -e 's/\[d\]/./gi' \
        -e 's/\\././g' "$INPUT" | sort -u > sorted_input.txt
}

function add_headers {
    local OUTPUT="$1"
    local HEADERS='url,resource,fileType,md5,sha256,source'
    echo "$HEADERS" > "$OUTPUT"
}

function download_file {
    local URL="$1"
    curl -m 20 -s "$URL" -o downloadedFile
}

function obfuscate_url {
    local URL="$1"
    echo "$URL" | sed -e 's/http/hxxp/gi' -e 's/\./[.]/g' 
}

function url_path {
    local URL="$1"
    echo "$1" | cut -d / -f 4- | sed 's/^/\//g'
}

function mime_type {
    file --mime-type downloadedFile
}

function md5_chechsum {
    md5sum downloadedFile | awk '{print $1}'
}

function sha256_checksum {
    sha256sum downloadedFile | awk '{print $1}'
}

function write_data {
    local OBFURL="$1"
    local URLPATH="$2"
    local FILETYPE="$3"
    local MD5="$4"
    local SHA256="$5"
    local OUTPUT="$6"
    echo "$OBFURL,$URLPATH,$FILETYPE,$MD5,$SHA256,download" >> "$OUTPUT"
}

#------------------------------------------------------------------------------#

# Set variables for the script arguments
INPUT="$1"
OUTPUT="$2"

# Get the analysis time
LINECOUNT=$(line_count "$INPUT")
URLCOUNT=$(url_count "$LINECOUNT")
echo -e "We have $URLCOUNT files to download. Hang tight...\n"

# Sort and deobfuscate the URLs
sort_urls "$INPUT"

# Write the headers to the output file
add_headers "$OUTPUT"

# Loop through the sorted list of URLs
while read -r URL
do
    rm -f downloadedFile
    echo "Attempting to download file from $URL..."
    download_file "$URL"

    OBFURL=$(obfuscate_url "$URL")
    URLPATH=$(url_path "$URL")
    if [[ ! -f downloadedFile ]]
    then
        echo "$OBFURL,$URLPATH,,,,file not found" >> "$OUTPUT"
        continue
    fi
    FILEOUTPUT=$(mime_type)
    FILETYPE=${FILEOUTPUT#downloadedFile: *}
    MD5=$(md5_chechsum)
    SHA256=$(sha256_checksum)
    write_data "$OBFURL" "$URLPATH" "$FILETYPE" "$MD5" "$SHA256" "$OUTPUT"

    rm -f downloadedFile
done<sorted_input.txt

# Remove the sorted list of URLs
rm -f sorted_input.txt
