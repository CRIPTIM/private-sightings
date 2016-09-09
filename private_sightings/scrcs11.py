# Copyright 2016 Tim van de Kamp. All rights reserved.
# Use of this source code is governed by the MIT license that can be
# found in the LICENSE file.
#
# Package private_sightings is an implementation of the proposed scheme
# by Shi et al. “Privacy-Preserving Aggregation of Time-Series Data”.
# This proof of concept implementation is evaluated in the paper
# “Private Sharing of IOCs and Sightings”.
from charm.toolbox.ecgroup import ECGroup, G, ZR

class SCRCS11:
    """
    Implementation of the SCRCS11 scheme by Shi et al. to aggregate
    time-series data in a privacy-friendly way.
    """

    def setup(self, curve, subscribers):
        """
        Setup the scheme using a trusted third party.
        """
        group = ECGroup(curve)
        g = group.random(G)

        ak = 0
        sk = list()
        for i in range(subscribers):
            key = group.random(ZR)
            ak -= key
            sk.append(key)

        self.pp = {'subscribers': subscribers, 'group': group, 'g': g}
        self.ak = ak
        self.sk = sk

        self.baby_steps = None

        return (self.pp, self.ak, self.sk)

    def encrypt(self, sk, sightings, identifier, timestamp):
        """
        Encrypt the number of sightings for an IOC identifier and a
        timestamp.
        """
        hash_value = self.pp['group'].hash(str(identifier) + timestamp, G)
        ct = (self.pp['g'] ** sightings) * (hash_value ** sk)
        return ct

    def exhaustive_search(self, value):
        """
        Compute the dlog using exhaustive search.
        """
        group_order = int(self.pp['group'].order())
        accumulator = self.pp['group'].init(G)
        for x in range(group_order):
            if accumulator == value:
                return x
            accumulator *= self.pp['g']

        return None

    def baby_giant(self, value):
        """
        Compute the dlog using baby-step giant-step.
        """
        baby_steps = len(self.baby_steps)
        giant_steps = int(self.pp['group'].order()) // baby_steps + 1

        giant_step = self.pp['g'] ** baby_steps
        accumulator = value
        for x in range(giant_steps):
            lookup = int(self.pp['group'].zr(accumulator))
            if lookup in self.baby_steps:
                return x*baby_steps + self.baby_steps[lookup]
            accumulator /= giant_step

        return None

    def dlog(self, value, dlog_method=None, dlog_steps=None):
        """
        Compute the discrete logarithm of 'value' to the generator of
        the public parameters as base.
        """
        if dlog_method == 'baby-giant':
            # Build a baby-step giant-step table to solve the dlog if it
            # doesn't exists already
            if self.baby_steps is None:
                baby_steps = dict()
                accumulator = self.pp['group'].init(G)
                for x in range(dlog_steps):
                    x_coordinate = self.pp['group'].zr(accumulator)
                    baby_steps[int(x_coordinate)] = x
                    accumulator *= self.pp['g']

                self.baby_steps = baby_steps

            # Make the giant steps
            return self.baby_giant(value)
        elif self.dlog_method == 'exhaustive_search':
            return self.exhaustive_search(value)
        else:
            raise Exception('Unknown dlog method.')

    def aggregate_decrypt(self, ak, identifier, timestamp, ciphertexts,
            dlog_method='baby-giant', dlog_steps=1024):
        """
        Aggregate ciphertexts to learn the total number of sightings.
        """
        assert len(ciphertexts) == self.pp['subscribers'], \
                'aggregate_decrypt requires exactly one ciphertext for \
each subscriber'

        aggregate = self.pp['group'].hash(str(identifier) + timestamp, G) ** ak
        for ciphertext in ciphertexts:
            aggregate *= ciphertext

        return self.dlog(aggregate, dlog_method, dlog_steps)
