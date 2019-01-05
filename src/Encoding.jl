
# Floating point encoding for the Paillier cryptosystem.

export Encoding, Encoded, EncryptedNumber, encode, decode, encode_and_encrypt
export decrypt_and_decode, decrease_exponent_to

"""
A datatype for describing an encoding scheme.

julia> encoding = Encoding(Float64, public_key, 16)

"""
struct Encoding
    datatype::DataType
    public_key::PublicKey
    base::Int64
end


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
    EncryptedNumber

Datatype for representing an encrypted (and [`Encoded`](@ref)) number.

# Examples
```jldoctest
julia> EncryptedNumber(encoded_number, public_key)
42
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


function encode_and_encrypt(plaintext::Number, encoding::Encoding)
    encoded_x = encode(plaintext, encoding)
    return EncryptedNumber(encoded_x, encoding.public_key)
end

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

There is also a version that acts on [`EncodedNumber`](@ref) instances.
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
        #prec_exponent = ?
    end

    # Note If encoding has a max exponent we would enforce here
    exponent = prec_exponent
    return encode(scalar, encoding, exponent)
end
function encode(scalar::Number, encoding::Encoding, exponent::Int64)::Encoded
    int_rep = intrep(scalar, encoding.public_key.n, encoding.base, exponent)
    return Encoded(encoding, int_rep, exponent)
end

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
    # Keep error free by using Rational{BigInt} math
    m = Rational{BigInt}(mantissa)
    b = Rational{BigInt}(encoding.base)

    return encoding.datatype(m * b^exponent)
end

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
