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

## Examples

A number of examples can be found in the [examples](./examples) folder.

Run examples with Julia:

```
$ julia --project examples/raw_cryptosystem.jl
```

### Quick Example

This is using the *raw* paillier cryptosystem (no encoding).

```julia
julia> using Paillier
julia> pub, priv = generate_paillier_keypair(1024)
julia> a = encrypt(pub, 10)
julia> b = encrypt(pub, 50)
julia> decrypt(priv, a)
10
julia> decrypt(priv, a + 5)
15
julia> # obfuscate before sharing an encrypted number:
julia> c = obfuscate(2a + b);
julia> typeof(c)
Encrypted
julia> decrypt(priv, c)
70
```

## Floating point encoding

To work with floating point numbers we follow the encoding scheme of 
[python-paillier](https://python-paillier.readthedocs.io/en/develop/phe.html#phe.paillier.EncodedNumber).
First create an `Encoding` for the native Julia type, the public key and
(optionally) the `base` to use.

```julia
julia> keysize = 2048
julia> publickey, privatekey = generate_paillier_keypair(keysize)
julia> encoding = Encoding{Float32}(publickey)
julia> a = Float32(π)
julia> b = 100
julia> enc1 = encode_and_encrypt(a, encoding)
julia> decrypt_and_decode(privatekey, enc1)
3.1415927f0
julia> enc1.exponent
-6
julia> enc2 = encode_and_encrypt(b, encoding)
julia> enc3 = decrypt_and_decode(privatekey, enc1 + enc2)
julia> enc3
103.141594f0
julia> decrypt_and_decode(privatekey, enc1 - 20.0)
-16.858408f0
```

There are still rough edges when working with higher precision datatypes
such as `BigFloat`. For now I'd recommend encoding either Float32 or Float64.  

## Array Support

To avoid wasting space having multiple copies of the same `PublicKey` I've added an 
`EncryptedArray` type that looks like an array of `EncryptedNumber` objects, but only
stores the underlying ciphertexts and one copy of shared metadata such as the public 
key, the encoding and the exponent. 


```julia
julia> publickey, privatekey = generate_paillier_keypair(2048)
julia> a = [0.0, 1.2e3, 3.14, π]
julia> encoding = Encoding{Float32}(publickey)
julia> enca = encode_and_encrypt(a, encoding);
julia> decrypt_and_decode(privatekey, enca)
4-element Array{Float32,1}:
    0.0      
 1200.0      
    3.1399999
    3.1415927
julia> encb = 2 * enca;
julia> decrypt_and_decode(privatekey, encb)
4-element Array{Float32,1}:
    0.0      
 2400.0      
    6.2799997
    6.2831855
julia> decrypt_and_decode(privatekey, reduce(+, encb))
2412.5632f0
julia> enca.is_obfuscated
true
julia> encb.is_obfuscated
false
julia> encb = obfuscate(encb);
julia> encb.is_obfuscated
true
```

See [encryptedarray.jl](./src/encryptedarray.jl) for the implementation.

### Broadcasting Support

`Paillier.jl` makes some effort towards supporting multidimensional arrays:

```julia
julia> x = [[0, 1] [345, 32410] [3, 784564]]
julia> publickey, privatekey = generate_paillier_keypair(4096)
julia> encoding = Encoding{Float32}(publickey)
julia> encrypted = encode_and_encrypt(x, encoding)
julia> encrypted.public_key == publickey
true
julia> typeof(encrypted), size(encrypted)
(EncryptedArray{BigInt,2}, (2, 3))
julia> decrypt_and_decode(privatekey, encrypted)
2×3 Array{Float32,2}:
 0.0    345.0       3.0
 1.0  32410.0  784564.0
julia> decrypt_and_decode(privatekey, [4, 2] .* encrypted .+ 100)
2×3 Array{Float32,2}:
 100.0   1480.0  112.0      
 102.0  64920.0    1.56923e6
```

Finally an example calling `dot` from LinearAlgebra between an encrypted
and non encrypted matrix:

```julia
julia> using Paillier, LinearAlgebra
julia> a = [[1,2] [2,3]]
julia> b = [[1,2] [2,3]]
julia> publickey, privatekey = generate_paillier_keypair(4096)
julia> encoding = Encoding{Float32}(publickey)
julia> ea = encode_and_encrypt(a, encoding)
julia> decrypt_and_decode(privatekey, dot(ea, b))
18.0f0
```

