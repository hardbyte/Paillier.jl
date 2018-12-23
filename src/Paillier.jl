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
export PrivateKey, PublicKey, Ciphertext, encrypt, decrypt, add, generate_paillier_keypair

const Ciphertext = BigInt

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


PublicKey(p, q) = PublicKey(p * q)
PublicKey(n::BigInt) = PublicKey(n, n^2, n + 1)

PrivateKey(public_key::PublicKey, p::BigInt, q::BigInt) = PrivateKey(public_key, p, q, public_key.n)
function PrivateKey(public_key::PublicKey, p::BigInt, q::BigInt, n::BigInt)
    l = (p - 1) * (q - 1)
    m = invmod(l, n)
    PrivateKey(l, m, public_key)
end

function encrypt(pub::PublicKey, m)
    rng = RandomDevice()
    r = rand(rng, big.(2:pub.n))
    rn = powermod(r, pub.n, pub.n_sq)
    gm = mod( (pub.n * m) + 1, pub.n_sq )
    c::Ciphertext = mod(gm * rn, pub.n_sq)
end

function decrypt(priv::PrivateKey, c)
    x = powermod(c, priv.l, priv.public_key.n_sq) - 1
    m = mod(div(x, priv.public_key.n) * priv.m, priv.public_key.n)
end

function add(pub::PublicKey, c1::Ciphertext, c2::Ciphertext)
    return c = mod(c1 * c2, pub.n_sq)
end

function multiply(pub::PublicKey, ciphertext::BigInt, plaintext::Number)
    max_int = BigInt(round(pub.n / 3) - 1)
    if pub.n - max_int <= plaintext
        neg_ciphertext = invmod(ciphertext, pub.n_sq)
        neg_scalar = pub.n - plaintext
        return powermod(neg_ciphertext, neg_scalar, pub.n_sq)
    else
        return powermod(ciphertext, plaintext, pub.n_sq)
    end
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