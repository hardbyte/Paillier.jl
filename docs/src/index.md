# Paillier.jl

Paillier.jl is divided into two layers: the core cryptosystem, and a higher level
layer which can deal with encoding floating point numbers and vectors of encrypted
numbers.


```@contents
```


# Installation

`Paillier.jl` has been registered so install with:

```julia
]add Paillier
```

# Examples

A number of examples can be found in the [examples](./examples) folder.

Run examples with Julia:

```
$ julia --project examples/raw_cryptosystem.jl
```

# Features

## Raw Paillier

Low level example using the *raw* paillier cryptosystem (no encoding).

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
such as `BigFloat`. For now I'd recommend encoding either `Float32` or `Float64`.  

## User Defined Encoding

This example uses a custom `Encoding` to take a `Measurement` and encode it for encryption
as an `EncryptedArray` containing the value and the uncertainty.

```julia
import Paillier
using Measurements
import Base.+

keysize = 2048
base = 64

MyType = Measurement{Float16}
publickey, privatekey = Paillier.generate_paillier_keypair(keysize)
encoding = Paillier.Encoding{MyType}(publickey, base)

# Support encoding any Measurement by encoding the value and error separately
# This will create an EncodedArray
function Paillier.encode(scalar::MyType, encoding::Paillier.Encoding{Measurement{T}}) where T
    internal_encoding = Paillier.Encoding{T}(encoding.public_key, encoding.base)
    encodings = Paillier.encode([scalar.val, scalar.err], internal_encoding)
    # create a copy of the EncodedArray with our Measurement encoding type
    Paillier.EncodedArray(encodings.plaintexts, encoding)
end

function Paillier.decode(encoded::Paillier.EncodedArray, exponent::Int64, encoding::Paillier.Encoding{Measurement{T}}) where T
    internal_encoding = Paillier.Encoding{T}(encoding.public_key, encoding.base)
    return measurement(
        Paillier.decode(encoded.plaintexts[1].value, exponent, internal_encoding),
        Paillier.decode(encoded.plaintexts[2].value, exponent, internal_encoding)
    )
end

"""
Because we are end up with an array of encrypted numbers
we may want to override some of the broadcast/array functionality
"""
+(enc_a::Paillier.EncryptedArray, plaintext::Measurement) = enc_a + Paillier.encode(plaintext, enc_a.encoding)

a = Measurement{Float16}(2000 ± 10)
b = Measurement{Float16}(100 ± 1)

enc1 = Paillier.encode_and_encrypt(a, encoding)
enc2 = Paillier.encode_and_encrypt(b, encoding)

enc3 = enc1 + enc2

c = Paillier.decrypt_and_decode(privatekey, enc3)
println("Adding encrypted Measurement numbers: D(E($a) + E($b)) = $c")

# Dircetly use our previously defined encoding function
encoded_b = Paillier.encode(b, enc3.encoding)
d = Paillier.decrypt_and_decode(privatekey, enc3 + encoded_b)
println("Adding encrypted number with encoded but unencrypted number (with uncertainty): D(E($c) + $b) = $d")

# Dircetly add a non encoded Measurement number
d = Paillier.decrypt_and_decode(privatekey, enc3 + b)
println("Adding encrypted number with Meaurement number: D(E$c) + $b) = $d")

# Subtraction
enc4 = Paillier.decrypt_and_decode(privatekey, enc3 - Paillier.encode_and_encrypt(a, enc3.encoding))
println("Subtract a constant (with uncertainty) from an encrypted number: D(E($c) - $a) = $enc4")

# Multiplication
enc5 = Paillier.decrypt_and_decode(privatekey, 3*enc1)
println("Scaling an encrypted Measurement number: 3 * $a = $enc5")

```

## Array Support

To avoid wasting space having multiple copies of the same `PublicKey` I've added an 
`EncryptedArray` type that behaves like an array of `EncryptedNumber` objects, but only
stores one copy of shared metadata such as the public 
key, the encoding and the exponent along with the underlying ciphertexts.


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

### Broadcasting

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


# Changelog

## Version 0.3.0

Introduces a breaking change in the encoded type, which should allow easier composition with other Julia modules.

To migrate replace `Encoding(Float32, publickey)` with `Encoding{Float32}(publickey)`.

