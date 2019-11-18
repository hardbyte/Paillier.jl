import Base.+
import Base.-
import Base.*
import Base.zero

struct PublicKey
    n::BigInt
    n_sq::BigInt
    g::BigInt
end

struct PrivateKey
    l::BigInt
    m::BigInt
    public_key::PublicKey
end

"""
    Ciphertext

The raw encrypted information is always a `Ciphertext` which is
simply an alias of BigInt.
"""
const Ciphertext = BigInt

Base.show(io::IO, pk::PrivateKey) = print(io, "PrivateKey(hash=$(hash(pk.l) + hash(pk.m)))")
Base.show(io::IO, pk::PublicKey) = print(io, "PublicKey(bits=$(Int64(ceil(log2(pk.n)))), hash=$(hash(pk.n)))")


"""
    Encrypted(ciphertext, public_key)
    Encrypted(ciphertext, public_key, is_obfuscated::Bool)

An `Encrypted` is the `Paillier.jl` library's low level encrypted type. This simple
object that includes the `ciphertext`, `public_key` and tracks whether obfuscation
has occurred (assumed as `false` if not provided).
"""
struct Encrypted
    ciphertext::Ciphertext
    public_key::PublicKey
    is_obfuscated::Bool
end
Encrypted(ciphertext::Ciphertext, public_key::PublicKey) = Encrypted(ciphertext, public_key, false)

PublicKey(p, q) = PublicKey(p * q)
PublicKey(n::BigInt) = PublicKey(n, n^2, n + 1)

PrivateKey(public_key::PublicKey, p::BigInt, q::BigInt) = PrivateKey(public_key, p, q, public_key.n)
function PrivateKey(public_key::PublicKey, p::BigInt, q::BigInt, n::BigInt)
    l = (p - 1) * (q - 1)
    m = invmod(l, n)
    PrivateKey(l, m, public_key)
end

"""
    obfuscate(encrypted)
    obfuscate(rng, encrypted)

Salt the `Encrypted` with a new random number. Required before
sharing ciphertexts with another party.
"""
obfuscate(x::Encrypted) = x.is_obfuscated ? x : Encrypted(obfuscate(default_rng(), x.public_key, x.ciphertext), x.public_key, true)
obfuscate(rng::AbstractRNG, x::Encrypted) = x.is_obfuscated ? x : Encrypted(obfuscate(x.public_key, x.ciphertext), x.public_key, true)
obfuscate(pub::PublicKey, x::Ciphertext) = obfuscate(default_rng(), pub, x)
function obfuscate(rng::AbstractRNG, pub::PublicKey, x::Ciphertext)::Ciphertext
    r = random_lt_n(rng, pub.n)
    rn = powermod(r, pub.n, pub.n_sq)
    return mod(x * rn, pub.n_sq)
end

"""
    encrypt_raw(public_key, message)

Internal version of `encrypt` that returns the raw [`Ciphertext`](@ref) - which is just
a `BigInt`. Note this includes **obfuscation** so
a directly encrypted unsigned integer is safe to share.
"""
function encrypt_raw(pub::PublicKey, m::Integer)::Ciphertext
    gm = mod((pub.n * m) + 1, pub.n_sq )
    return obfuscate(pub, gm)
end

"""
    encrypt(public_key, message)

Encrypt a message with a given public key and return an [`Encrypted`](@ref).
The `message` must be a positive integer under `public_key.n` - following Julia's
Int64 type **larger numbers will wrap around and not throw an error**.

See [`decrypt`](@ref) if you'd like your original message back.
"""
function encrypt(pub::PublicKey, m::Integer)::Encrypted
    if m < 0
        throw(DomainError("Can't encrypt negative integers without encoding"))
    end
    ciphertext = encrypt_raw(pub, m)
    return Encrypted(ciphertext, pub, true)
end

"""
    decrypt(private_key, ciphertext::Ciphertext)
    decrypt(private_key, ciphertext::Encrypted)

The inverse of [`encrypt`](@ref), uses the `private_key` to decrypt an encrypted
message (`ciphertext`) to a positive integer less than `public_key.n`.
The result is always a `BigInt`.

# Examples

```jldoctest
julia> publickey, privatekey = generate_paillier_keypair(128);
julia> ciphertext = encrypt(publickey, 10);
julia> decrypt(privatekey, ciphertext)
10

```
"""
function decrypt(priv::PrivateKey, c::Ciphertext)::BigInt
    x = powermod(c, priv.l, priv.public_key.n_sq) - 1
    return mod(div(x, priv.public_key.n) * priv.m, priv.public_key.n)
end
function decrypt(priv::PrivateKey, enc::Encrypted)::BigInt
    if priv.public_key != enc.public_key
        throw(ArgumentError("Trying to decrypt with a different private key."))
    end
    c = enc.ciphertext
    return decrypt(priv, c)
end

zero(encrypted::Encrypted) = encrypt(encrypted.public_key, 0)

raw_add(public_key::PublicKey, c1::Ciphertext, c2::Ciphertext) = mod(c1 * c2, public_key.n_sq)

"""
    +(::Encrypted, ::Number)
    +(::Encrypted, ::Encrypted)

Homomorphic addition. Add an [`Encrypted`](@ref) to either a plaintext or another encrypted.

Note a plaintext number will be automatically encrypted and therefore must meet the same
conditions outlined in [`encrypt`](@ref) - i.e. positive integers under `public_key.n`.

# Examples
```jldoctest
julia> publickey, privatekey = generate_paillier_keypair(128)

julia> c1 = encrypt(publickey, 10)

julia> decrypt(privatekey, c1 + 90)
100

julia> c2 = encrypt(publickey, 1000)

julia> decrypt(privatekey, c1 + c2)
1010
```
"""
+(encrypted::Encrypted, plaintext::Number) = plaintext + encrypted
+(plaintext::Int64, encrypted::Encrypted) =  encrypted + BigInt(plaintext)
+(plaintext::UInt64, encrypted::Encrypted) = encrypted + plaintext
+(encrypted::Encrypted, plaintext::BigInt) = plaintext >= 0 ? encrypted + encrypt(encrypted.public_key, plaintext) : throw(DomainError("Can't encrypt negative numbers directly'"))
function +(c1::Encrypted, c2::Encrypted)::Encrypted
    if c1.public_key != c2.public_key
        throw(ArgumentError("Can only add Encrypted with the same public key"))
    end
    return Encrypted(raw_add(c1.public_key, c1.ciphertext, c2.ciphertext), c1.public_key)
end

function _multiply_via_inversion(ciphertext, public_key, plaintext)
    # Very large ciphertext. Use inversion trick
    neg_ciphertext = invmod(ciphertext, public_key.n_sq)
    neg_scalar = public_key.n - plaintext
    new_ciphertext = powermod(neg_ciphertext, neg_scalar, public_key.n_sq)
end

function raw_multiply(public_key::PublicKey, ciphertext::Ciphertext, plaintext::Integer)::Ciphertext
    if public_key.n - BigInt(floor(public_key.n // 3)) <= plaintext
        new_ciphertext = _multiply_via_inversion(ciphertext, public_key, plaintext)
    else
        new_ciphertext = powermod(ciphertext, plaintext, public_key.n_sq)
    end
    return new_ciphertext
end

"""
    *(::Encrypted, ::Integer)

Homomorphic multiplication. Allows the multiplication of an Encrypted and cleartext integer.
"""
*(encrypted::Encrypted, plaintext::Number) = plaintext * encrypted
function *(plaintext::Integer, encrypted::Encrypted)
    new_ciphertext = raw_multiply(encrypted.public_key, encrypted.ciphertext, plaintext)
    return Encrypted(new_ciphertext, encrypted.public_key)
end
