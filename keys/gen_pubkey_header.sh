#!/usr/bin/env bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

destfile="$1"


cat > "$destfile" << EOF
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef SAMPLES_REMOTE_ATTESTATION_PUBKEY_H
#define SAMPLES_REMOTE_ATTESTATION_PUBKEY_H

#define ENCLAVE_PUBKEY_SIZE 624

EOF

printf 'static const char OTHER_ENCLAVE_PUBLIC_KEY[][624] = {' >> "$destfile"
for ((i = 1; i <= 2; i++)); do
    while IFS="" read -r p || [ -n "$p" ]
    do
        printf '\n    \"%s\\n\"' "$p" >> "$destfile"
    done < "../keys/public$i.pem"
    printf ','$'\n' >> "$destfile"
done

while IFS="" read -r p || [ -n "$p" ]
    do
        printf '\n    \"%s\\n\"' "$p" >> "$destfile"
    done < "../keys/public$i.pem"
    printf '};'$'\n' >> "$destfile"

cat >> "$destfile" << EOF

#endif /* SAMPLES_REMOTE_ATTESTATION_PUBKEY_H */
EOF
