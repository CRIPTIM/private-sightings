#!/usr/bin/env python3
# Copyright 2016 Tim van de Kamp. All rights reserved.
# Use of this source code is governed by the MIT license that can be
# found in the LICENSE file.
#
# This file contains example code how to use the package.
from charm.toolbox.eccurve import prime256v1
from datetime import date
from private_sightings.scrcs11 import SCRCS11

# Initialize scheme
scheme = SCRCS11()

# Number of subscribers
subscribers = 10
# Setup the scheme by a trusted third party using curve P-256
scheme.setup(prime256v1, subscribers)

# Set an IOC identifier and the timestamp of today
identifier = 'IOC ID'
today = date.today().strftime('%Y-%m-%d')

# Create the ciphertext for each subscriber
ciphertexts = list()
for subscriber in range(subscribers):
    ciphertexts.append(scheme.encrypt(scheme.sk[subscriber], 1,
        identifier, today))

# Compute the aggregate using the aggregation key AK
print('Aggregated sum = {}'.format(scheme.aggregate_decrypt(scheme.ak,
    identifier, today, ciphertexts)))
