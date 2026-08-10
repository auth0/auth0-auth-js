#!/bin/bash
set -e

FILE="/Users/tushar.pandey/src/auth0-auth-js/packages/auth0-server-js/src/server-client.spec.ts"

# Create backup
cp "$FILE" "$FILE.bak"

# Extract HEAD section (fullResponse tests) - lines 8475-9613
sed -n '8475,9613p' "$FILE.bak" | grep -v "^<<<<<<< HEAD" | grep -v "^=======$" | grep -v "^>>>>>>> 20f0a9a" > /tmp/head_section.txt

# Extract theirs section (requestOptions tests) - lines 8513-9973
sed -n '8513,9973p' "$FILE.bak" | grep -v "^<<<<<<< HEAD" | grep -v "^=======$" | grep -v "^>>>>>>> 20f0a9a" > /tmp/theirs_section.txt

echo "Extracted sections for manual merge"
