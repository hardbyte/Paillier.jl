```@meta
CurrentModule = Paillier
```

# Encoding Floats and other Julia DataTypes

Full example showing homomorphic operations on floating point numbers:

```jldoctest
julia> keysize = 2048
julia> publickey, privatekey = generate_paillier_keypair(keysize)
julia> encoding = Encoding{Float32}(publickey)
julia> a = Float32(π)
julia> enc1 = encode_and_encrypt(a, encoding)
julia> decrypt_and_decode(privatekey, enc1)
3.1415927f0
julia> enc1.exponent
-6
julia> b = 100
julia> enc2 = encode_and_encrypt(b, encoding)
julia> decrypt_and_decode(privatekey, enc1 + enc2)
103.141594f0
julia> decrypt_and_decode(privatekey, enc1 - 20.0)
-16.858408f0

```


## API


```@docs
encode_and_encrypt

decrypt_and_decode
```

## Types

```@docs
Encoding

Encoded

EncryptedNumber
```

## User Defined Decoding

Say you wanted to carry out Partially Homomorphic operations on values with uncertainty using
the fantastic [Meaurements](https://github.com/JuliaPhysics/Measurements.jl) package.

Do achieve this you need to define your `Encoding` type, and add methods to
`encode` and `decode` the new `Encoding` type.

```julia
import Paillier
using Measurements

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

a = Measurement{Float16}(2000 ± 10)
b = Measurement{Float16}(100 ± 1)

enc1 = Paillier.encode_and_encrypt(a, encoding)
enc2 = Paillier.encode_and_encrypt(b, encoding)

enc3 = enc1 + enc2

c = Paillier.decrypt_and_decode(privatekey, enc3)
println("Adding encrypted numbers (with uncertainty): $c")
```
