#!/bin/bash
clear
echo "Generating output of test runs of tests/regression/03-practical"
dstpath=/home/alex/Documents/git/analyzer/testResults/
for folder in "/home/alex/Documents/git/analyzer/tests/regression"/*; do
	foldername=$(basename "$folder")
	echo "$foldername"
	mkdir "/home/alex/Documents/git/analyzer/testResults"/$foldername
	for entry in "/home/alex/Documents/git/analyzer/tests/regression/03-practical"/*; do
	  
	  basename=$(basename "$entry")
	  dst="${dstpath%.c}"$foldername"/"$basename".sarif"
	  ./goblint --sarif -o "$dst" "$entry" 
	done
done
