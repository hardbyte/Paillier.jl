# Usage

After [Installation](@ref) of the package, you can start using it with:

```julia
using Paillier
```


## Key Generation

To begin you will need a keypair - a public and private Paillier key.

Generate a public and private key of default length using [`generate_paillier_keypair`](@ref):

```@repl rawcrypto
using Paillier
publickey, privatekey = generate_paillier_keypair()
```

```@meta
DocTestSetup = quote
    using Paillier
    publickey, privatekey = generate_paillier_keypair(256)
end
```

## Raw Paillier cryptosystem

At the lowest level we can `encrypt` and `decrypt` (positive) integers using the
*raw* paillier cryptosystem without encoding. Addition between encrypted numbers,
and multiplication of an encrypted number and a *plaintext* number works.

The `publickey` is used for encryption via [`encrypt`](@ref), and `privatekey`
is required to [`decrypt`](@ref).


```@repl rawcrypto
a = encrypt(publickey, 10)
b = encrypt(publickey, 50)
decrypt(privatekey, a)
decrypt(privatekey, a + 5)
c = 2a + b
decrypt(privatekey, c)
c.is_obfuscated
```


!!! note

    The raw encrypted numbers above are **not** ready for sharing. Users must manually
    call [`obfuscate`](@ref). This is to allow any homomorphic
    operations to be completed before running the expensive obfuscation code.



Always [`obfuscate`](@ref) before sharing an encrypted number:

```@repl rawcrypto
(2a + b).is_obfuscated
c = obfuscate(2a + b)
c.is_obfuscated
decrypt(privatekey, c)
```

!!! note

    Attempting to encrypt a negative integer will result in a `DomainError`:

    ```
    julia> encrypt(pub, -10)
    ERROR: DomainError with Can't encrypt negative integers without encoding:
    ```

## Floating point encoding

To work with negative and floating point numbers we follow the encoding scheme of
[python-paillier](https://python-paillier.readthedocs.io/en/develop/phe.html#phe.paillier.EncodedNumber).

Create an [`Encoding`](@ref) for the type to *encode*.


### Example encoding Float32 numbers

```@repl
using Paillier
publickey, privatekey = generate_paillier_keypair()
encoding = Encoding{Float32}(publickey)
a = Float32(π)
enc1 = encode_and_encrypt(a, encoding)
decrypt_and_decode(privatekey, enc1)
enc1.exponent
enc2 = encode_and_encrypt(100, encoding)
decrypt_and_decode(privatekey, enc1 + enc2)
decrypt_and_decode(privatekey, enc1 - 20.0)
```

!!! note

    There are still rough edges when working with higher precision datatypes
    such as `BigFloat`. For now I'd recommend encoding either `Float32` or `Float64`.  

### User Defined Encoding

See [encoding](./encoding.md) for an example creating a custom `Encoding` to take a
`Measurement` and encode it for encryption as an `EncryptedArray` containing both
the value and the uncertainty in encrypted form.

## Array Support

To avoid wasting space having multiple copies of the same `PublicKey` use the
`EncryptedArray` type that behaves like an array of `EncryptedNumber` objects, but only
stores one copy of shared metadata such as the public
key, the encoding and the exponent along with the underlying ciphertexts.

```@docs
Paillier.EncryptedArray
```

### Paillier operations on an encrypted vector of floats

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

Finally an example calling `dot` from `LinearAlgebra` between an encrypted
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
