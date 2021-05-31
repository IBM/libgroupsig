#!/bin/env bash

schemes="BBS04 GL19 PS16 KLAP20 DL21 DL21SEQ"
for scheme in $schemes; do
	awk -v scheme="$scheme" '$1==scheme { print $2, $5, $6 }' $1 > "$scheme.log"
done
