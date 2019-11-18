# Floating point encoding for the Paillier cryptosystem.
import LinearAlgebra.dot

export Encoding, Encoded, EncryptedNumber, encode, decode, encode_and_encrypt
export decrypt_and_decode, decrease_exponent_to

"""
    Encoding{::DataType}(::PublicKey)
    Encoding{::DataType,(::PublicKey, base::Int64)

A datatype for describing a fixed point encoding scheme for Julia DataTypes.

The public key is included as the encoding is effected by the maximum representable
integer which varies with the `public_key`.

Setting a base value is optional - other Paillier implementations may use a  different
base.

# Examples

Specifying the optional base for encoding a Float64:

```
julia> encoding = Encoding{Float64}(public_key, 64)
```
"""
struct Encoding{T}
    public_key::PublicKey
    base::Int64
end

Encoding{T}(public_key::PublicKey) where T = Encoding{T}(public_key, 16)

"""
    max_int(::PublicKey)

The maximum signed integer for our encoding system.
We use a full third of the range for overflow detection.
"""
max_int(public_key::PublicKey) = max_int(public_key.n)
max_int(n::BigInt) = (n-1)//3

"""
A datatype for a **plaintext** encoded number.
Returned by the `encode` methods.

Represents the Julia value as a `BigInt`.
"""
struct Encoded
    encoding::Encoding
    value::BigInt
    exponent::Int64
end

"""
    EncryptedNumber(::Encrypted, ::Encoding, exponent::Int64)
    EncryptedNumber(::Encoded, ::PublicKey)

Datatype for representing an Encrypted number with a known Encoding.

# Examples

```@meta
public_key, priv = generate_paillier_keypair(128)
encoding = Encoding{Float32}(publickey)
```

```jldoctest
julia> encoded_number = encode(23.4, encoding)
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

Base.show(io::IO, enc::EncryptedNumber) = print(io, "EncryptedNumber(exponent=$(enc.exponent), hash=$(hash(enc.encrypted)))")


"""
    encode_and_encrypt(plaintext::Number, encoding::Encoding)
    encode_and_encrypt(plaintext::Number, encoding::Encoding, exponent::Int64)

Encode the `plaintext` number using given `encoding` and encrypt
using the `PublicKey` from the `encoding`.
"""
function encode_and_encrypt(plaintext::Number, encoding::Encoding)
    encoded_x = encode(plaintext, encoding)
    return encrypt(encoded_x, encoding.public_key)
end
function encode_and_encrypt(plaintext::Number, encoding::Encoding, exponent::Int64)
    encoded_x = encode(plaintext, encoding, exponent)
    return encrypt(encoded_x, encoding.public_key)
end

encrypt(plaintext::Encoded, public_key::PublicKey) = EncryptedNumber(plaintext, public_key)

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
    @debug "Decreasing exponent of Encoded"
    if new_exponent > enc.exponent
        throw(DomainError("new exponent should be more negative than existing"))
    end
    factor = enc.encoding.base^(enc.exponent - new_exponent)
    value = mod(enc.value * factor, enc.encoding.public_key.n)

    return Encoded(enc.encoding, value, new_exponent)
end

function intrep(scalar::Number, n::BigInt, base::Int64, exponent::Int64)::BigInt
    scalar = Rational{BigInt}(scalar)
    base = Rational{BigInt}(base)

    rational_rep = scalar * base^(-exponent)
    int_rep = BigInt(round(rational_rep))

    if abs(int_rep) > max_int(n)
        throw(DomainError("attempt to encode unrepresentable number $scalar * $base^$(-exponent) = $int_rep  where max_int = $(max_int(n))"))
    end
    # Map negative numbers into [0, n]
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
encode(scalar::Integer, encoding::Encoding{T}) where T <: Number = encode(scalar, encoding, 0)
function encode(scalar::Number, encoding::Encoding{T})::Encoded where T <: Number
    if isinteger(scalar) && scalar < max_int(encoding.public_key)
        prec_exponent = 0
    elseif typeof(scalar) <: AbstractFloat
        # Precision calculation
        # Ideally we'd like to encode with at least as much precision
        # as the encoded type, but this may not be possible if the
        # keysize is small or the precision(datatype) is large.

        # number of bits the Encoded type can represent
        mantisa_digits = precision(T)

        # Can't use a precision greater than the keysize will allow
        keysize_bits = Int64(ceil(log2(encoding.public_key.n//3)))

        # Find the base-2 exponent of the float.
        bin_flt_exp = frexp(scalar)[2]

        # the base-2 exponent of the least significant bit
        bin_lsb_exponent = bin_flt_exp - mantisa_digits

        # A negative base-2 exponent more than our keysize.
        if bin_lsb_exponent < -keysize_bits
            @info "clamping as $bin_lsb_exponent < $(-keysize_bits)"
            bin_lsb_exponent = -keysize_bits
        end

        # Convert to base encoding.base
        prec_exponent = Int64(floor(bin_lsb_exponent/log2(encoding.base)))

        # If the int_rep is too large to fit we can modify the exponent

        while scalar * BigFloat(encoding.base)^-prec_exponent > encoding.public_key.n//3
            @info "Current int_rep is going to be too big. Increasing exponent.", prec_exponent
            prec_exponent += 1
        end

    else
        throw(DomainError("don't know the precision for this"))
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
function decode(encoded::BigInt, exponent::Int64, encoding::Encoding{T}) where T
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

    return T(m * b^exponent)
end


zero(a::EncryptedNumber) = encode_and_encrypt(0, a.encoding, a.exponent)

# Homomorphic operations

-(a::EncryptedNumber, b) = a + (-1*b)

# Tell the compiler we can swap the order...
+(a, b::EncryptedNumber) = b + a

# Note we modify the encoded exponent in cleartext, not in the cipherspace.
#+(a::EncryptedNumber, b::Number) = a + EncryptedNumber(encode(b, a.encoding, a.exponent), a.encoding.public_key)
+(a::EncryptedNumber, b::Number) = a + encode_and_encrypt(b, a.encoding, a.exponent)

function +(a::EncryptedNumber, b::EncryptedNumber)
    if (a.encoding != b.encoding)
        throw(DomainError("Can only add EncryptedNumbers that share encoding and public key"))
    end

    # In order to add two numbers, their exponents must match
    a, b = match_exponents(a, b)

    if (a.exponent == b.exponent)
        return EncryptedNumber(a.encrypted + b.encrypted,
                               a.encoding,
                               a.exponent)
    else
        throw("couldn't match EncryptedNumber's exponents ($(a.exponent) & $(b.exponent))")
    end
end


*(b::Union{Number, Encoded}, a::EncryptedNumber) = a * b
*(a::EncryptedNumber, b::Number) = a * encode(b, a.encoding)
function *(a::EncryptedNumber, b::Encoded)
    product = a.encrypted * b.value
    EncryptedNumber(product, a.encoding, a.exponent + b.exponent)
end

# Should this be here? Is depending on LinearAlgebra necassary?
dot(a::EncryptedNumber, b::Number) = a * b
