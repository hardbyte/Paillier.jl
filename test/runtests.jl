using Test

include("../src/Paillier.jl")
using Main.Paillier

# Global testing settings

KEYSIZES = [128, 256, 512, 1024, 2048]

KEYS = Dict()

@debug "Generating test key pairs"
for keysize in KEYSIZES
    publickey, privatekey = generate_paillier_keypair(keysize)
    KEYS[keysize] = (publickey, privatekey)
end

include("test_cryptosystem.jl")
include("test_encoding.jl")
include("test_encryptedarray.jl")

