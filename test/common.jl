using Test
using Paillier

# Global testing settings

KEYSIZES = [128, 256, 512, 1024, 2048]

KEYS = Dict()

@debug "Generating test key pairs"
for keysize in KEYSIZES
    publickey, privatekey = generate_paillier_keypair(keysize)
    KEYS[keysize] = (publickey, privatekey)
end

