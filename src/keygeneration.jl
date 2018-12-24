
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
