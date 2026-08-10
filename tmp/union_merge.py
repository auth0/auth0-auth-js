#!/usr/bin/env python3
"""
Union-merge conflict resolution: keep BOTH sides
- fullResponse tests (HEAD) → keep
- requestOptions tests (theirs) → keep
- Where tests overlap method signatures, merge them
"""

import re

file_path = "/Users/tushar.pandey/src/auth0-auth-js/packages/auth0-server-js/src/server-client.spec.ts"

with open(file_path, 'r') as f:
    lines = f.readlines()

result = []
i = 0
conflict_count = 0
in_conflict = False
head_section = []
theirs_section = []

while i < len(lines):
    line = lines[i]

    if line.startswith('<<<<<<< HEAD'):
        in_conflict = True
        conflict_count += 1
        head_section = []
        theirs_section = []
        i += 1
        continue

    if in_conflict and line.startswith('======='):
        # Switch from HEAD to theirs
        i += 1
        while i < len(lines) and not lines[i].startswith('>>>>>>> '):
            theirs_section.append(lines[i])
            i += 1

        # Now at >>>>>>>
        if i < len(lines):
            i += 1  # Skip the >>>>>>> line

        # Decision logic: UNION merge
        # If HEAD tests fullResponse and theirs tests requestOptions, keep both
        # If they're testing the same thing, pick one (theirs has the updated impl)

        head_text = ''.join(head_section)
        theirs_text = ''.join(theirs_section)

        # If HEAD has test bodies with fullResponse, keep it
        # theirs section is always requestOptions tests, keep it

        # Check if HEAD is actually test code (not just setup)
        if 'test(' in head_text or 'describe(' in head_text:
            result.extend(head_section)

        # Always add theirs (requestOptions tests)
        result.extend(theirs_section)

        in_conflict = False
        continue

    if in_conflict:
        # Collecting HEAD section
        head_section.append(line)
        i += 1
        continue

    # Normal line
    result.append(line)
    i += 1

# Write result
with open(file_path, 'w') as f:
    f.writelines(result)

print(f"Resolved {conflict_count} conflicts using UNION strategy")

# Verify no remaining conflicts
with open(file_path, 'r') as f:
    content = f.read()
remaining = content.count('<<<<<<< HEAD')
print(f"Remaining conflict markers: {remaining}")
