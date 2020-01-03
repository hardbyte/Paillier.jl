# Paillier.jl

```@contents
```

Paillier.jl is divided into two layers: the core cryptosystem, and a higher level
layer which can deal with encoding floating point numbers and vectors of encrypted
numbers.

!!! note

    Important notes on security.

    We don't obfuscate the results of encrypted math operations by default. This is an
    optimization copied from `python-paillier`, however after any homomorphic operation -
    before sharing an `EncryptedNumber` or `EncryptedArray` you must call `obfuscate()`
    to secure the ciphertext. Ideally this will occur behind the scenes at serialization
    time, but this library does not help with serialization (yet).

    Be warned that constant time functions have **not** been used, proceed with
    extreme caution if your application could be susceptible to timing side
    channel attacks.


## Installation

`Paillier.jl` has been registered so install with Julia's package manager with:

```julia
] add Paillier
```

## Examples

A number of examples can be found in the [examples](https://github.com/hardbyte/Paillier.jl/tree/master/examples) folder.

Run individual examples with Julia:

```
$ julia --project examples/raw_cryptosystem.jl
```

## Changelog

### Version 0.3.0

Introduces a breaking change in the encoded type, which should allow easier composition with other Julia modules.

To migrate replace `Encoding(Float32, publickey)` with `Encoding{Float32}(publickey)`.
