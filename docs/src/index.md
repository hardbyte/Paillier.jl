# Paillier.jl

```@contents
```

Paillier.jl is divided into two layers: the core cryptosystem, and a higher level
layer which can deal with encoding floating point numbers and vectors of encrypted
numbers.

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
