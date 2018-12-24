"""
# module Paillier

# Examples

```jldoctest
julia> pub, priv = generate_paillier_keypair(1024)
julia> c = encrypt(pub, 10)
julia> decrypt(priv, add(pub, c, encrypt(pub, 20)))
30
```
"""
module Paillier

using Random, Primes
include("utilities.jl")
export PrivateKey, PublicKey, EncryptedNumber, encrypt, decrypt, generate_paillier_keypair

import Base.+
import Base.*

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

struct EncryptedNumber
    ciphertext::BigInt
    public_key::PublicKey
end

PublicKey(p, q) = PublicKey(p * q)
PublicKey(n::BigInt) = PublicKey(n, n^2, n + 1)

PrivateKey(public_key::PublicKey, p::BigInt, q::BigInt) = PrivateKey(public_key, p, q, public_key.n)
function PrivateKey(public_key::PublicKey, p::BigInt, q::BigInt, n::BigInt)
    l = (p - 1) * (q - 1)
    m = invmod(l, n)
    PrivateKey(l, m, public_key)
end

function encrypt(pub::PublicKey, m)::EncryptedNumber
    rng = RandomDevice()
    r = rand(rng, big.(2:pub.n))
    rn = powermod(r, pub.n, pub.n_sq)
    gm = mod( (pub.n * m) + 1, pub.n_sq )
    return EncryptedNumber(mod(gm * rn, pub.n_sq), pub)
end

function decrypt(priv::PrivateKey, enc::EncryptedNumber)
    if priv.public_key != enc.public_key
        throw(ArgumentError("Trying to decrypt with a different private key."))
    end
    c = enc.ciphertext
    x = powermod(c, priv.l, priv.public_key.n_sq) - 1
    return mod(div(x, priv.public_key.n) * priv.m, priv.public_key.n)
end

+(encrypted::EncryptedNumber, plaintext::Int) = encrypted + encrypt(encrypted.public_key, plaintext)
function +(c1::EncryptedNumber, c2::EncryptedNumber)::EncryptedNumber
    if c1.public_key != c2.public_key
        throw(ArgumentError("Can only add EncryptedNumbers with the same public key"))
    end
    return EncryptedNumber(mod(c1.ciphertext * c2.ciphertext, c1.public_key.n_sq), c1.public_key)
end


*(encrypted::EncryptedNumber, plaintext::Number) = plaintext * encrypted
function *(plaintext::Number, encrypted::EncryptedNumber)
    max_int = BigInt(round(encrypted.public_key.n / 3) - 1)
    if encrypted.public_key.n - max_int <= plaintext
        neg_ciphertext = invmod(encrypted.ciphertext, encrypted.public_key.n_sq)
        neg_scalar = encrypted.public_key.n - plaintext
        new_ciphertext = powermod(neg_ciphertext, neg_scalar, encrypted.public_key.n_sq)
    else
        new_ciphertext = powermod(encrypted.ciphertext, plaintext, encrypted.public_key.n_sq)
    end
    return EncryptedNumber(new_ciphertext, encrypted.public_key)
end

function generate_paillier_keypair(n_length=2048)
    n_len = BigInt(0)
    n = BigInt(0)
    p = BigInt(0)
    q = BigInt(0)
    n_length = BigInt(n_length)
    n_on_2 = BigInt(round(n_length//2))

    while n_len != n_length
        p = nbit_prime_of_size(n_on_2)
        q = p
        while q == p
            q = nbit_prime_of_size(n_on_2)
        end
        n = BigInt(p * q)
        n_len = length(string(n; base = 2))
    end
    public_key = PublicKey(n)
    private_key = PrivateKey(public_key, p, q)

    return public_key, private_key
end

end