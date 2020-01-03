# Usage

After installing the package, you can start using it with

```julia
using Paillier
```

## Key Generation

To begin you will need a keypair - a public and private Paillier key.

```@docs
Paillier.generate_paillier_keypair
```

 
## Raw Paillier cryptosystem

At the lowest level we can `encrypt` and `decrypt` (positive) integers using the 
*raw* paillier cryptosystem - that is with no encoding.

```jldoctest
julia> using Paillier
julia> pub, priv = generate_paillier_keypair(1024)
julia> a = encrypt(pub, 10)
julia> b = encrypt(pub, 50)
julia> decrypt(priv, a)
10
julia> decrypt(priv, a + 5)
15
julia> c = 2a + b;
julia> typeof(c)
Encrypted
julia> decrypt(priv, c)
70
```

Note that addition between encrypted numbers, and multiplication of an encrypted
number and a *plaintext* number works.

!!! note

    The raw encrypted numbers above are **not** ready for sharing. Users must manually
    call `obfuscate` once all the mathematical operations have been completed.

     
```@docs
Paillier.obfuscate
```

Always obfuscate before sharing an encrypted number:

```julia
julia> (2a + b).is_obfuscated
false
julia> c = obfuscate(2a + b)
julia> c.is_obfuscated
true
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

Create an `Encoding` for the type to *encode*.

```@docs
Paillier.Encoding
```

### Example encoding Float32 numbers

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

!!! note

    There are still rough edges when working with higher precision datatypes
    such as `BigFloat`. For now I'd recommend encoding either `Float32` or `Float64`.  

### User Defined Encoding

See [encoding](./encoding) for an example creating a custom `Encoding` to take a 
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
