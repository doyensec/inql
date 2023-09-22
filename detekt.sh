#!/bin/bash

# Collect the list of files as arguments and convert spaces to commas
FILES=$(echo "$@" | tr ' ' ',' | sed 's/,$//')

# Run detekt with the comma-separated file list
detekt --input "$FILES"
