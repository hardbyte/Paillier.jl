const DEFAULT_KEY_LENGTH = 2048

"""
    generate_paillier_keypair([rng=GLOBAL_RNG], n_length=2048)

Generate a new Paillier keypair of given bit length.

Returns a 2-tuple of the public and private key.
"""
generate_paillier_keypair(n_length=DEFAULT_KEY_LENGTH) = generate_paillier_keypair(default_rng(), n_length)
function generate_paillier_keypair(rng::AbstractRNG, n_length=DEFAULT_KEY_LENGTH)
    n_len = BigInt(0)
    n = BigInt(0)
    p = BigInt(0)
    q = BigInt(0)
    n_length = BigInt(n_length)
    n_on_2 = BigInt(round(n_length//2))

    while n_len != n_length
        p = nbit_prime_of_size(rng, n_on_2)
        q = p
        while q == p
            q = nbit_prime_of_size(rng, n_on_2)
        end
        n = BigInt(p * q)
        n_len = length(string(n; base = 2))
    end
    public_key = PublicKey(n)
    private_key = PrivateKey(public_key, p, q)

    return public_key, private_key
end
