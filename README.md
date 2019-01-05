**Paillier.jl** is a [Julia](http://julialang.org/) package implementing the basics of the *Paillier* 
partially homomorphic cryptosystem.

Based off the [sketch](https://github.com/snipsco/paillier-libraries-benchmarks/tree/master/julia-sketch) 
written by [Morten Dahl](https://github.com/mortendahl) at [Snips](https://snips.ai), and the 
[python-paillier](https://github.com/n1analytics/python-paillier) library written by 
[N1 Analytics](https://www.n1analytics.com).

The homomorphic properties of the paillier crypto system are:

* Encrypted numbers can be multiplied by a non encrypted scalar.
* Encrypted numbers can be added together.

# Warning - Here be dragons.

This is rough! Don't use for anything serious yet! Not reviewed by a cryptographer.

In particular we don't obfuscate the results of encrypted math operations by default. This is an 
optimization copied from python-paillier, however after any homomorphic operation - before sharing
an `EncryptedNumber` or `EncryptedArray` you must call `obfuscate()` to secure the ciphertext. 

Ideally this will occur behind the scenes at serialization time.

## Quick Example

This is using the *raw* paillier cryptosystem.

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
EncryptedNumber
julia> decrypt(priv, c)
70
```

## Floating point encoding

```julia
julia> keysize = 2048
julia> base = 16
julia> publickey, privatekey = generate_paillier_keypair(keysize)
julia> encoding = Encoding(Float16, publickey, base)
julia> a = 2000
julia> b = 100
julia> enc1 = encode_and_encrypt(a, encoding)
julia> enc2 = encode_and_encrypt(b, encoding)
julia> enc3 = decrypt_and_decode(privatekey, enc1 + enc2)
julia> enc3
2100.0
julia> enc4 = decrypt_and_decode(privatekey, enc1 - 20.0)
julia> enc4
1980.0
```

## Array Support

To avoid wasting space having multiple copies of the same `PublicKey` I've added an 
`EncryptedArray` type that shares one public key for an array of ciphertexts.

```julia
julia> a = [0,1,2,3,4,5]
julia> enca = encrypt(publickey, a)
julia> encb = 2 * enca
julia> decrypt(privatekey, reduce(+, encb))
30
```

See [encryptedarray.jl](./src/encryptedarray.jl) for implementation.

### Broadcasting Support

I've made some effort towards supporting multidimensional arrays:

```julia
julia> x = [[0, 1] [345, 32410] [3, 784564]]
julia> publickey, privatekey = generate_paillier_keypair(4096)
julia> encrypted = encrypt(publickey, x)
julia> encrypted.public_key == publickey
true
julia> typeof(encrypted), size(encrypted)
(EncryptedArray{BigInt,2}, (2, 3))
julia> decrypt(privatekey, encrypted)
2×3 Array{BigInt,2}:
 0    345       3
 1  32410  784564
julia> decrypt(privatekey, [4, 2] .* encrypted .+ 100)
2×3 Array{BigInt,2}:
 100   1480      112
 102  64920  1569228
```

However not everything works, e.g. the `LinearAlgebra.dot` function.

## More Examples

A number of examples can (eventually) be found [here](./examples), for now just some 
[benchmarking](http://nbviewer.ipython.org/github/hardbyte/Paillier.jl/blob/master/examples/benchmarking.ipynb).
