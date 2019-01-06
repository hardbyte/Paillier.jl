"""
This file adds support for working with arrays of encrypted numbers.
"""

export encrypt, decrypt, EncryptedArray

"""
A vector version of [`Encrypted`](@ref).
"""
struct EncryptedArray{Ciphertext, N} <: AbstractArray{Ciphertext, N}
    ciphertexts::Array{Ciphertext, N}
    public_key::PublicKey
    is_obfuscated::Bool
end

EncryptedArray(xs::Array{Ciphertext}, public_key::PublicKey) = EncryptedArray(xs, public_key, false)

function encrypt(pub::PublicKey, plaintext::Array{Int64})
    if all(x >= 0 for x in plaintext)
        return encrypt(pub, Array{UInt64}(plaintext))
    else
        throw(DomainError("Can't directly encrypt negative numbers'"))
    end
end

function encrypt(pub::PublicKey, plaintext::Array{UInt64})
    encrypted = [encrypt_raw(pub, x) for x in plaintext]
    return EncryptedArray(encrypted, pub, true)
end

function decrypt(priv::PrivateKey, encryptedarray::EncryptedArray)
    if priv.public_key != encryptedarray.public_key
        throw(ArgumentError("Trying to decrypt with a different private key."))
    end
    plaintext = [decrypt(priv, x) for x in encryptedarray.ciphertexts]
    return plaintext
end

function obfuscate(x::EncryptedArray)::EncryptedArray
    if x.is_obfuscated
        return x
    else
        return EncryptedArray(
            [obfuscate(x.public_key, ciphertext) for ciphertext in x.ciphertexts],
            x.public_key,
            true)
    end
end

*(encryptedarray::EncryptedArray, scalar::Number) = *(scalar, encryptedarray)
function *(scalar::Number, encryptedarray::EncryptedArray)
    wrapped_multiply(plaintext) = raw_multiply(encryptedarray.public_key, plaintext, scalar)
    new_ciphertexts = map(wrapped_multiply, encryptedarray.ciphertexts)
    return EncryptedArray(new_ciphertexts, encryptedarray.public_key)
end

+(enc_a::EncryptedArray, plaintext::Array) = enc_a + encrypt(enc_a.public_key, plaintext)
function +(enc_a::EncryptedArray, enc_b::EncryptedArray)
    if enc_a.public_key != enc_b.public_key
        throw(ArgumentError("Trying to add vectors encrypted with a different keypair."))
    end
    wrapped_add(c1, c2) = raw_add(enc_a.public_key, c1, c2)
    new_ciphertexts = [wrapped_add(a,b) for (a,b) in zip(enc_a.ciphertexts, enc_b.ciphertexts)]
    return EncryptedArray(new_ciphertexts, enc_a.public_key)
end

"""
Iterating over an EncryptedArray should give Encrypted objects and not the
raw Ciphertext.
"""
function Base.iterate(enc::EncryptedArray, state=1)
    if state > length(enc.ciphertexts)
        return nothing
    else
        return Encrypted(enc.ciphertexts[state], enc.public_key), state+1
    end
end

Base.eltype(::Type{EncryptedArray}) = Encrypted
Base.length(x::EncryptedArray) = length(x.ciphertexts)
Base.size(x::EncryptedArray) = size(x.ciphertexts)
Base.showarg(io::IO, A::EncryptedArray, toplevel) = print(io, typeof(A), " with public key '", A.public_key, "'")
Base.IndexStyle(::Type{<:EncryptedArray}) = IndexLinear()
Base.BroadcastStyle(::Type{<:EncryptedArray}) = Broadcast.ArrayStyle{EncryptedArray}()
function Base.getindex(A::EncryptedArray, i::T) where {T}
    indexed = getindex(A.ciphertexts, i::T)
    if typeof(indexed) == Ciphertext
        return Encrypted(indexed, A.public_key)
    else
        return EncryptedArray(indexed, A.public_key)
    end
end

function Base.setindex!(A::EncryptedArray{T,N}, val::Encrypted, inds) where {T,N}
    setindex!(A.ciphertexts, val.ciphertext, inds)
end
Base.convert(::Type{Ciphertext}, enc::Encrypted) = enc.ciphertext

function Base.similar(A::EncryptedArray, ::Type{T}, dims::Dims) where {T}
    ciphertexts = similar(A.ciphertexts, dims)
    EncryptedArray(ciphertexts, A.public_key)
end

# Required for broadcasting e.g. `100 .+ encrypted`
function Base.similar(bc::Broadcast.Broadcasted{Broadcast.ArrayStyle{EncryptedArray}}, ::Type{ElType}) where ElType
    # Scan the inputs for the EncryptedArray:
    A = find_ea(bc)
    # Use the public_key field of A to create the output
    return EncryptedArray(similar(A.ciphertexts, axes(bc)), A.public_key)
end

"`A = find_ea(As)` returns the first EncryptedArray among the arguments."
find_ea(bc::Base.Broadcast.Broadcasted) = find_ea(bc.args)
find_ea(args::Tuple) = find_ea(find_ea(args[1]), Base.tail(args))
find_ea(x) = x
find_ea(a::EncryptedArray, rest) = a
find_ea(::Any, rest) = find_ea(rest)
