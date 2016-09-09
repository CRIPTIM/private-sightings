#!/usr/bin/env python3
# Copyright 2016 Tim van de Kamp. All rights reserved.
# Use of this source code is governed by the MIT license that can be
# found in the LICENSE file.
#
# This file contains benchmarking code for the implementation.
from charm.toolbox.eccurve import prime256v1
from charm.toolbox.ecgroup import ECGroup, G, ZR
from datetime import date
from private_sightings.scrcs11 import SCRCS11
from math import sqrt

# Initialize scheme
scheme = SCRCS11()
subscribers = 10
scheme.setup(prime256v1, subscribers)

# Setup of the benchmark
assert scheme.pp['group'].InitBenchmark(), "failed to initialize benchmark"
runs = 31
t_value = 2.750
trials = 5000
print('{:3s} {:18s} {:18s} {:18s} {:18s}'.format('alg', 'mean', 'var', 'sd', 'ci'))

# Benchmark encrypt()
identifier = 'IOC ID'
today = date.today().strftime('%Y-%m-%d')
run_times = list()
for run in range(runs):
    scheme.pp['group'].StartBenchmark(["RealTime"])
    for i in range(trials):
        scheme.encrypt(scheme.sk[0], 1, identifier, today)
    scheme.pp['group'].EndBenchmark()

    msmtDict = scheme.pp['group'].GetGeneralBenchmarks()
    run_times.append(msmtDict["RealTime"])

sample_mean = sum(run_times) / (runs * trials)
sample_variance = 0
for run_time in run_times:
    sample_variance += (sample_mean - run_time/trials) * (sample_mean - run_time/trials)
sample_variance /= (runs - 1)

print('{:3s} {:1.16f} {:1.16f} {:1.16f} {:1.16f}'.format('enc',
    sample_mean, sample_variance, sqrt(sample_variance), t_value * sqrt(sample_variance/(runs-1))))

# Benchmark aggregate_decrypt()
for subscribers in range(1, 201):
    scheme = SCRCS11()
    scheme.setup(prime256v1, subscribers)
    assert scheme.pp['group'].InitBenchmark(), "failed to initialize benchmark"

    ciphertexts = list()
    for subscriber in range(subscribers):
        ciphertexts.append(scheme.encrypt(scheme.sk[subscriber], 1, identifier, today))

    run_times = list()
    for run in range(runs):
        scheme.pp['group'].StartBenchmark(["RealTime"])
        for i in range(trials):
            scheme.aggregate_decrypt(scheme.ak, identifier, today, ciphertexts)
        scheme.pp['group'].EndBenchmark()

        msmtDict = scheme.pp['group'].GetGeneralBenchmarks()
        run_times.append(msmtDict["RealTime"])

    sample_mean = sum(run_times) / (runs * trials)
    sample_variance = 0
    for run_time in run_times:
        sample_variance += (sample_mean - run_time/trials) * (sample_mean - run_time/trials)
    sample_variance /= (runs - 1)

    print('{:-3d} {:1.16f} {:1.16f} {:1.16f} {:1.16f}'.format(subscribers,
        sample_mean, sample_variance, sqrt(sample_variance), t_value * sqrt(sample_variance/(runs-1))))
