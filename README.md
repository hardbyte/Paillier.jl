**Paillier.jl** is a [Julia](http://julialang.org/) package implementing the basics of
 the *Paillier* partially homomorphic cryptosystem.

[![Build Status](https://travis-ci.org/hardbyte/Paillier.jl.svg?branch=master)](https://travis-ci.org/hardbyte/Paillier.jl)
[![](https://img.shields.io/badge/docs-dev-blue.svg)](https://hardbyte.github.io/Paillier.jl/dev)

The homomorphic properties of the paillier crypto system are:

* Encrypted numbers can be multiplied by a non encrypted scalar.
* Encrypted numbers can be added together.

# Warning - Here be dragons.

This is rough! Don't use for anything serious yet! Not reviewed by a cryptographer.

Constant time functions have not been used, so this could be susceptible to timing
side channel attacks.

We don't obfuscate the results of encrypted math operations by default. This is an 
optimization copied from `python-paillier`, however after any homomorphic operation -
before sharing an `EncryptedNumber` or `EncryptedArray` you must call `obfuscate()`
to secure the ciphertext. Ideally this will occur behind the scenes at serialization
time, but this library does not help with serialization (yet).

Based off the [sketch](https://github.com/snipsco/paillier-libraries-benchmarks/tree/master/julia-sketch) 
written by [Morten Dahl](https://github.com/mortendahl) at [Snips](https://snips.ai), and the 
[python-paillier](https://github.com/data61/python-paillier) library written by 
[CSIRO's Data61](https://data61.csiro.au) as part of N1 Analytics.
