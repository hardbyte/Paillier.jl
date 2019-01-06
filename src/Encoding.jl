
# Floating point encoding for the Paillier cryptosystem.

export Encoding, Encoded, EncryptedNumber, encode, decode, encode_and_encrypt
export decrypt_and_decode, decrease_exponent_to

"""
    Encoding(::DataType, ::PublicKey)
    Encoding(::DataType, ::PublicKey, base::Int64)

A datatype for describing an encoding scheme.

The public key is included as the encoding is effected by the maximum representable
integer which varies with the `public_key`. Although I could be convinced to change
this.

# Examples

Setting a base value is optional:
```
julia> encoding = Encoding(Float64, public_key, 64)
```

Full example showing homomorphic operations on floating point numbers:

```jldoctest
julia> keysize = 2048
julia> publickey, privatekey = generate_paillier_keypair(keysize)
julia> encoding = Encoding(Float32, publickey)
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
"""
struct Encoding
    datatype::DataType
    public_key::PublicKey
    base::Int64
end
Encoding(datatype::DataType, public_key::PublicKey) = Encoding(datatype, public_key, 16)

"""
A datatype for a **plaintext** encoded number.
Returned by the `encode` methods.
"""
struct Encoded
    encoding::Encoding
    value::BigInt
    exponent::Int64
end

"""
    EncryptedNumber(::Encrypted, ::Encoding, exponent::Int64)
    EncryptedNumber(::Encoded, ::PublicKey)

Datatype for representing an encrypted (and [`Encoded`](@ref)) number.

# Examples
```jldoctest
julia> EncryptedNumber(encoded_number, public_key)
```
"""
struct EncryptedNumber
    encrypted::Encrypted
    encoding::Encoding
    exponent::Int64
end

function EncryptedNumber(encoded::Encoded, public_key::PublicKey)
    encrypted = encrypt(public_key, encoded.value)
    return EncryptedNumber(encrypted, encoded.encoding, encoded.exponent)
end

"""
    encode_and_encrypt(plaintext::Number, encoding::Encoding)

Encode the `plaintext` number using given `encoding` and encrypt
using the `PublicKey` from the `encoding`.
"""
function encode_and_encrypt(plaintext::Number, encoding::Encoding)
    encoded_x = encode(plaintext, encoding)
    return EncryptedNumber(encoded_x, encoding.public_key)
end

"""
    decrypt_and_decode(privatekey::PrivateKey, enc::EncryptedNumber)

Decrypt an `EncryptedNumber` using the given `PrivateKey` and decode it
using the `EncryptedNumber`'s encoding.
"""
function decrypt_and_decode(privatekey::PrivateKey, enc::EncryptedNumber)
    decrypted = decrypt(privatekey, enc.encrypted)
    return decode(decrypted, enc.exponent, enc.encoding)
end


"""
    decrease_exponent_to(enc, new_exponent)

Compute an [`EncryptedNumber`](@ref) with the same value but a lower exponent.

We multiply the *encoded* value by the `Encoding.base` and decrement the
`EncryptedNumber.exponent` - such that the decoded value remains the same.

We can keep ratcheting down the [`EncryptedNumber`](@ref)'s exponent until the
encoded integer overflows. **This overflow may not be caught**.

There is also a (much faster) version that acts on [`EncodedNumber`](@ref)s.
"""
function decrease_exponent_to(enc::EncryptedNumber, new_exponent::Int64)::EncryptedNumber
    if new_exponent > enc.exponent
        throw(DomainError("New exponent should be more negative than existing"))
    end

    factor = Float64(enc.encoding.base^(enc.exponent - new_exponent))

    # This should get refactored into *(::EncryptedNumber, ::Number)
    encoded_factor = encode(factor, enc.encoding, 0)
    value = encoded_factor.value * enc.encrypted
    # Note we don't bother salting/obfuscating here.
    return EncryptedNumber(value, enc.encoding, new_exponent)
end

function decrease_exponent_to(enc::Encoded, new_exponent::Int64)::Encoded
    @info "Decreasing exponent of Encoded"
    if new_exponent > enc.exponent
        throw(DomainError("New exponent should be more negative than existing"))
    end
    factor = enc.encoding.base^(enc.exponent - new_exponent)
    value = mod(enc.value * factor, enc.encoding.public_key.n)

    return Encoded(enc.encoding, value, new_exponent)
end

function intrep(scalar::Number, n::BigInt, base::Int64, exponent::Int64)::BigInt
    scalar = Rational{BigInt}(scalar)
    base = Rational{BigInt}(base)

    int_rep = BigInt(round(scalar * base^(-exponent)))

    if abs(int_rep) > max_int(n)
        throw(DomainError("Attempt to encode unrepresentable number"))
    end
    return mod(int_rep, n)
end

"""
    encode(::Number, ::Encoding)
    encode(::Number, ::Encoding, exponent::Int64)

Encode a number **but don't encrypt it** for the given `Encoding` - producing an `Encoded`.
See [`encode_and_encrypt`](@ref) for a method that also encrypts. If the exponent is not
provided we attempt to match the precision of the passed julia type. See [`decode`](@ref) to
go the other direction.
"""
encode(scalar::Int64, encoding::Encoding) = encode(scalar, encoding, 0)
function encode(scalar::Number, encoding::Encoding)::Encoded
    if typeof(scalar) <: AbstractFloat
        mantisa_digits = precision(scalar)

        # Precision calculation
        bin_flt_exp = frexp(scalar)[2]
        bin_lsb_exponent = bin_flt_exp - mantisa_digits

        prec_exponent = Int64(floor(bin_lsb_exponent/log2(encoding.base)))

    elseif typeof(scalar) <: Integer
        prec_exponent = 0
    else
        throw(DomainError("Don't know the precision for this"))
    end

    # Note if encoding has a max exponent we would enforce here
    exponent = prec_exponent
    return encode(scalar, encoding, exponent)
end
function encode(scalar::Number, encoding::Encoding, exponent::Int64)::Encoded
    int_rep = intrep(scalar, encoding.public_key.n, encoding.base, exponent)
    return Encoded(encoding, int_rep, exponent)
end

"""
    decode(encoded::Encoded)
    decode(encoded::BigInt, exponent::Int64, encoding::Encoding)

The inverse of [`encode`](@ref), computes the decoding of the `Encoded` integer
representation.
"""
decode(encoded::Encoded) = decode(encoded.value, encoded.exponent, encoded.encoding)
function decode(encoded::BigInt, exponent::Int64, encoding::Encoding)
    max_num = max_int(encoding.public_key)
    if encoded >= encoding.public_key.n
        throw(ArgumentError("Attempt to decode corrupted ciphertext"))
    elseif encoded <= max_num
        # positive
        mantissa = encoded
    elseif encoded >= encoding.public_key.n - max_num
        # negative
        mantissa = encoded - encoding.public_key.n
    else
        throw(ArgumentError("Overflow detected"))
    end
    # Avoid rounding errors by using Rational{BigInt} math
    m = Rational{BigInt}(mantissa)
    b = Rational{BigInt}(encoding.base)

    return encoding.datatype(m * b^exponent)
end

# Homomorphic operations

-(a::EncryptedNumber, b) = a + (-1*b)

# Note we modify the encoded exponent in cleartext, not in the cipherspace.
+(a::EncryptedNumber, b::Number) = a + EncryptedNumber(encode(b, a.encoding, a.exponent), a.encoding.public_key)

function +(a::EncryptedNumber, b::EncryptedNumber)
    if (a.encoding != b.encoding)
        throw(DomainError("Can only add EncryptedNumbers that share encoding and public key"))
    end

    # In order to add two numbers, their exponents must match
    if a.exponent > b.exponent
        a = decrease_exponent_to(a, b.exponent)
    elseif a.exponent < b.exponent
        b = decrease_exponent_to(b, a.exponent)
    end

    if (a.exponent == b.exponent)
        return EncryptedNumber(a.encrypted + b.encrypted,
                               a.encoding,
                               a.exponent)
    else
        throw("Couldn't add EncryptedNumbers? $(a.exponent), $(b.exponent)")
    end
end


#TODO *
