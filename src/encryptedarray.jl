"""
This file adds support for working with arrays of encrypted numbers.

Any `Number` that can be [`Encoded`](@ref) can be efficiently
represented internally as an array of `Ciphertext` sharing common metadata
such as encoding and public key.
"""

export encode_and_encrypt, decrypt_and_decode, EncryptedArray

"""
    EncodedArray

A vector version of [`Encoded`](@ref)
"""
struct EncodedArray
    plaintexts::Array{Encoded}
    encoding::Encoding
end
EncodedArray(xs::Array{BigInt}, encoding::Encoding, exponent::Int64) = EncodedArray(
    [
        Encoded(encoding, x, exponent)
        for x in xs
    ], encoding)


"""
    EncryptedArray

A vector version of [`EncryptedNumber`](@ref).
"""
struct EncryptedArray{Ciphertext, N} <: AbstractArray{Ciphertext, N}
    ciphertexts::Array{Ciphertext, N}
    public_key::PublicKey
    is_obfuscated::Bool
    encoding::Encoding
    exponent::Int64
end

function EncryptedArray(xs::Array{EncryptedNumber})
    encoding = xs[1].encoding
    publickey = encoding.public_key
    exponent = minimum(x.exponent for x in xs)
    return EncryptedArray(
            [obfuscate(publickey, decrease_exponent_to(x, exponent).encrypted.ciphertext) for x in xs],
            publickey,
            true,
            encoding,
            exponent
        )
end

decrease_exponent_to(xs::EncryptedArray, exponent::Int64) = [decrease_exponent_to(x, exponent) for x in xs]

function _normalize_exponent(encoded::Array{Encoded})
    # Used to enforce that a single exponent is shared by all elements in an EncryptedArray
    exponent = minimum(x.exponent for x in encoded)
    return [decrease_exponent_to(x, exponent) for x in encoded]
end


"""
    encrypt(::Array{Encoded}, ::Encoding)
    encrypt(::Array{Encoded}, ::PublicKey)

Encrypt an array of encoded instances
"""
encrypt(encoded::Array{Encoded}, encoding::Encoding) = encrypt(encoded, encoding.public_key)
function encrypt(encoded::Array{Encoded}, public_key::PublicKey)
    encoded_array = EncodedArray(encoded, encoded[1].encoding)
    return encrypt(encoded_array, public_key)
end

encrypt(encoded::EncodedArray, encoding::Encoding) = encrypt(encoded, encoding.public_key)
function encrypt(encoded::EncodedArray, public_key::PublicKey)
    encrypted = [encrypt_raw(public_key, x.value) for x in encoded.plaintexts]
    # Is this valid to assume a single exponent for all EncodedArray instances?
    exponent = encoded.plaintexts[1].exponent
    return EncryptedArray(encrypted, public_key, true, encoded.encoding, exponent)
end

"""
    encode_and_encrypt(xs::Array{<:Number}, encoding::Encoding)
    encode_and_encrypt(xs::Array{<:Number}, encoding::Encoding, exponent::Int64)

Create an EncryptedArray of your plaintext numbers.
"""
function encode_and_encrypt(plaintext::Array{<:Number}, encoding::Encoding, exponent::Int64)
    encoded = encode(plaintext, encoding, exponent)
    return encrypt(encoded, encoding)
end

function encode_and_encrypt(plaintext::Array{<:Number}, encoding::Encoding)
    encoded = encode(plaintext, encoding)
    return encrypt(encoded, encoding.public_key)
end

# TODO can we splat everything after Array{}, ...T?
function encode(plaintext::Array{<:Number}, encoding::Encoding)
     encoded_values = _normalize_exponent([encode(x, encoding) for x in plaintext])
     return EncodedArray(encoded_values, encoding)
 end
encode(plaintext::Array{<:Number}, encoding::Encoding, exponent) = EncodedArray([encode(x, encoding, exponent) for x in plaintext], encoding)

function decrypt_and_decode(priv::PrivateKey, encryptedarray::EncryptedArray)
    if priv.public_key != encryptedarray.public_key
        throw(ArgumentError("Trying to decrypt with a different private key."))
    end
    raw_encoded = decrypt(priv, encryptedarray.ciphertexts)
    # raw_encoded is a BigInt array
    encoded = EncodedArray(raw_encoded, encryptedarray.encoding, encryptedarray.exponent)
    return decode(encoded, encryptedarray.exponent, encryptedarray.encoding)
end

decrypt(priv::PrivateKey, ciphertexts::Array{Ciphertext}) = [decrypt(priv, x) for x in ciphertexts]

# decode(encoded::Array{BigInt,1}, exponent::Int64, encoding::Encoding) = EncodedArray(
#     [decode(x, exponent, encoding) for x in encoded],
#     encoding
# )

decode(encoded::Array{Encoded}, exponent, encoding::Encoding) = [ dejcode(x, exponent, encoding) for x in encoded ]

function decode(encoded::EncodedArray, exponent::Int64, encoding::Paillier.Encoding{T}) where T
    return [decode(enc.value, exponent, encoding) for enc in encoded.plaintexts]
end

function obfuscate(x::EncryptedArray)::EncryptedArray
    if x.is_obfuscated
        return x
    else
        return EncryptedArray(
            [obfuscate(x.public_key, ciphertext) for ciphertext in x.ciphertexts],
            x.public_key,
            true,
            x.encoding,
            x.exponent
            )
    end
end


*(scalar::Number, encryptedarray::EncryptedArray) = encryptedarray * scalar
*(encodedScalar::Encoded, encryptedarray::EncryptedArray) = encryptedarray * encodedScalar
*(encryptedarray::EncryptedArray, scalar::Number) = encryptedarray * encode(scalar, encryptedarray.encoding)
function *(enc::EncryptedArray, scalar::Encoded)
    encrypted_scale(x::Ciphertext) = raw_multiply(enc.public_key, x, scalar.value)

    return EncryptedArray(
        encrypted_scale.(enc.ciphertexts),
        enc.public_key,
        false,
        enc.encoding,
        enc.exponent + scalar.exponent
        )
end

-(a::EncryptedArray, b::AbstractArray) = a + (-1*b)

+(enc_a::EncryptedArray, plaintext::Array{Number}) = enc_a + encode(plaintext, enc_a.encoding, enc_a.exponent)
+(enc_a::EncryptedArray, plaintext::EncodedArray) = enc_a + encrypt(plaintext, enc_a.encoding)
function +(a::EncryptedArray, b::EncryptedArray)
    if a.public_key != b.public_key
        throw(ArgumentError("Trying to add vectors encrypted with a different keypair."))
    end

    # In order to add two EncryptedArrays, their exponents must match
    a,b = match_exponents(a, b)

    wrapped_add(c1::Ciphertext, c2::Ciphertext) = raw_add(a.public_key, c1, c2)

    return EncryptedArray(
        [wrapped_add(c1,c2) for (c1,c2) in zip(a.ciphertexts, b.ciphertexts)],
        a.public_key,
        false,
        a.encoding,
        a.exponent
        )
end

"""
Iterating over an EncryptedArray yields [`EncryptedNumber`](@ref) objects and not the
raw Ciphertexts.
"""
function Base.iterate(enc::EncryptedArray, state=1)
    if state > length(enc.ciphertexts)
        return nothing
    else
        encrypted = Encrypted(enc.ciphertexts[state], enc.public_key, enc.is_obfuscated)
        return EncryptedNumber(encrypted, enc.encoding, enc.exponent), state+1
    end
end

Base.eltype(::Type{EncryptedArray}) = EncryptedNumber
Base.length(x::EncryptedArray) = length(x.ciphertexts)
Base.size(x::EncryptedArray) = size(x.ciphertexts)
Base.showarg(io::IO, A::EncryptedArray, toplevel) = print(io, typeof(A), " with public key '", A.public_key, "'")
Base.IndexStyle(::Type{<:EncryptedArray}) = IndexLinear()
Base.BroadcastStyle(::Type{<:EncryptedArray}) = Broadcast.ArrayStyle{EncryptedArray}()
function Base.getindex(A::EncryptedArray, i::T) where {T}
    indexed = getindex(A.ciphertexts, i::T)
    if typeof(indexed) == Ciphertext
        encrypted = Encrypted(indexed, A.public_key, A.is_obfuscated)
        return EncryptedNumber(encrypted, A.encoding, A.exponent)
    else
        # TODO Perhaps this should be a view instead of a new array...
        return EncryptedArray(indexed, A.public_key, A.is_obfuscated, A.encoding, A.exponent)
    end
end

function Base.setindex!(A::EncryptedArray{T,N}, val::Ciphertext, inds) where {T,N}
    setindex!(A.ciphertexts, ciphertext, inds)
end

function Base.setindex!(A::EncryptedArray{T,N}, val::EncryptedNumber, inds) where {T,N}
    setindex!(A.ciphertexts, val.encrypted.ciphertext, inds)
end

function Base.similar(A::EncryptedArray, ::Type{T}, dims::Dims) where {T}
    ciphertexts = similar(A.ciphertexts, dims)
    EncryptedArray(ciphertexts, A.public_key, A.is_obfuscated, A.encoding, A.exponent)
end

# Required for broadcasting e.g. `100 .+ encrypted`
function Base.similar(bc::Broadcast.Broadcasted{Broadcast.ArrayStyle{EncryptedArray}}, ::Type{ElType}) where ElType
    # Scan the inputs for the EncryptedArray:
    A = find_ea(bc)
    # create the output EncryptedArray of the desired shape
    return similar(A, axes(bc))
end

"`A = find_ea(As)` returns the first EncryptedArray among the arguments."
find_ea(bc::Base.Broadcast.Broadcasted) = find_ea(bc.args)
find_ea(args::Tuple) = find_ea(find_ea(args[1]), Base.tail(args))
find_ea(x) = x
find_ea(a::EncryptedArray, rest) = a
find_ea(::Any, rest) = find_ea(rest)
