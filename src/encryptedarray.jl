"""
This file adds support for working with arrays of encrypted numbers.

Any `Number` that can be [`Encoded`](@ref) can be efficiently
represented internally as an array of `Ciphertext` sharing common metadata
such as encoding and public key.
"""

export encode_and_encrypt, decrypt_and_decode, EncryptedArray

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

function _encrypt_encoded(encoded::Array{Encoded}, encoding::Encoding, exponent::Int64)
    encoded = [decrease_exponent_to(x, exponent) for x in encoded]
    encrypted = [encrypt_raw(encoding.public_key, x.value) for x in encoded]
    return EncryptedArray(encrypted, encoding.public_key, true, encoding, exponent)
end


"""
    encode_and_encrypt(xs::Array{<:Number}, encoding::Encoding)
    encode_and_encrypt(xs::Array{<:Number}, encoding::Encoding, exponent::Int64)

Create an EncryptedArray of your plaintext numbers.
"""
function encode_and_encrypt(plaintext::Array{<:Number}, encoding::Encoding, exponent::Int64)
    encoded = [encode(x, encoding) for x in plaintext]
    return _encrypt_encoded(encoded, encoding, exponent)
end

function encode_and_encrypt(plaintext::Array{<:Number}, encoding::Encoding)
    encoded = [encode(x, encoding) for x in plaintext]

    # We enforce that a single exponent is shared by the EncryptedArray
    exponent = minimum(x.exponent for x in encoded)

    return _encrypt_encoded(encoded, encoding, exponent)
end

function decrypt_and_decode(priv::PrivateKey, encryptedarray::EncryptedArray)
    if priv.public_key != encryptedarray.public_key
        throw(ArgumentError("Trying to decrypt with a different private key."))
    end
    encoded = [decrypt(priv, x) for x in encryptedarray.ciphertexts]
    return [decode(x, encryptedarray.exponent, encryptedarray.encoding) for x in encoded]
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

+(enc_a::EncryptedArray, plaintext::Array{Number}) = enc_a + encode_and_encrypt(plaintext, enc_a.encoding)
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
