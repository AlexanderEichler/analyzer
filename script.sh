#!/bin/bash
clear
echo "Generating output of test runs of tests/regression/03-practical"
dstpath=/home/alex/Documents/git/analyzer/testResults/
for entry in "/home/alex/Documents/git/analyzer/tests/regression/03-practical"/*; do
  echo "$entry"
  basename=$(basename "$entry")
  dst="${dstpath%.c}"$basename".sarif"
  ./goblint --sarif -o "$dst" "$entry" 
done

