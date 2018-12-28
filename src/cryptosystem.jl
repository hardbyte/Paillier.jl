import Base.+
import Base.*

struct PublicKey
    n::BigInt
    n_sq::BigInt
    g::BigInt
end

const Ciphertext = BigInt

struct PrivateKey
    l::BigInt
    m::BigInt
    public_key::PublicKey
end

struct EncryptedNumber
    ciphertext::Ciphertext
    public_key::PublicKey
    is_obfuscated::Bool
end
EncryptedNumber(ciphertext::Ciphertext, public_key::PublicKey) = EncryptedNumber(ciphertext, public_key, false)
PublicKey(p, q) = PublicKey(p * q)
PublicKey(n::BigInt) = PublicKey(n, n^2, n + 1)

PrivateKey(public_key::PublicKey, p::BigInt, q::BigInt) = PrivateKey(public_key, p, q, public_key.n)
function PrivateKey(public_key::PublicKey, p::BigInt, q::BigInt, n::BigInt)
    l = (p - 1) * (q - 1)
    m = invmod(l, n)
    PrivateKey(l, m, public_key)
end

"""
Version of encrypt that returns the Ciphertext (BigInt) instead
of an EncryptedNumber. Note this is "safely obfuscated".
"""
function encrypt_raw(pub::PublicKey, m)::Ciphertext
    gm = mod((pub.n * m) + 1, pub.n_sq )
    return obfuscate(pub, gm)
end

obfuscate(x::EncryptedNumber)::EncryptedNumber = x.is_obfuscated ? x : EncryptedNumber(obfuscate(x.public_key, x.ciphertext), x.public_key, true)
function obfuscate(pub::PublicKey, x::Ciphertext)::Ciphertext
    r = random_lt_n(pub.n)
    rn = powermod(r, pub.n, pub.n_sq)
    return mod(x * rn, pub.n_sq)
end


function encrypt(pub::PublicKey, m)::EncryptedNumber
    ciphertext = encrypt_raw(pub, m)
    return EncryptedNumber(ciphertext, pub, true)
end

function decrypt(priv::PrivateKey, c::Ciphertext)::BigInt
    x = powermod(c, priv.l, priv.public_key.n_sq) - 1
    return mod(div(x, priv.public_key.n) * priv.m, priv.public_key.n)
end

function decrypt(priv::PrivateKey, enc::EncryptedNumber)::BigInt
    if priv.public_key != enc.public_key
        throw(ArgumentError("Trying to decrypt with a different private key."))
    end
    c = enc.ciphertext
    return decrypt(priv, c)
end

raw_add(public_key::PublicKey, c1::Ciphertext, c2::Ciphertext) = mod(c1 * c2, public_key.n_sq)

+(encrypted::EncryptedNumber, plaintext::Number) = plaintext + encrypted
+(plaintext::Int64, encrypted::EncryptedNumber) =  encrypted + BigInt(plaintext)
+(plaintext::UInt64, encrypted::EncryptedNumber) = encrypted + plaintext
+(encrypted::EncryptedNumber, plaintext::BigInt) = plaintext >= 0 ? encrypted + encrypt(encrypted.public_key, plaintext) : throw(DomainError("Can't encrypt negative numbers directly'"))
function +(c1::EncryptedNumber, c2::EncryptedNumber)::EncryptedNumber
    if c1.public_key != c2.public_key
        throw(ArgumentError("Can only add EncryptedNumbers with the same public key"))
    end
    return EncryptedNumber(raw_add(c1.public_key, c1.ciphertext, c2.ciphertext), c1.public_key)
end

function raw_multiply(public_key::PublicKey, ciphertext::Ciphertext, plaintext::Integer)::Ciphertext
    max_int = BigInt(round(public_key.n / 3) - 1)
    if public_key.n - max_int <= plaintext
        neg_ciphertext = invmod(ciphertext, public_key.n_sq)
        neg_scalar = public_key.n - plaintext
        new_ciphertext = powermod(neg_ciphertext, neg_scalar, public_key.n_sq)
    else
        new_ciphertext = powermod(ciphertext, plaintext, public_key.n_sq)
    end
    return new_ciphertext
end

*(encrypted::EncryptedNumber, plaintext::Number) = plaintext * encrypted
function *(plaintext::Number, encrypted::EncryptedNumber)
    plaintext = Integer(plaintext)
    new_ciphertext = raw_multiply(encrypted.public_key, encrypted.ciphertext, plaintext)
    return EncryptedNumber(new_ciphertext, encrypted.public_key)
end
