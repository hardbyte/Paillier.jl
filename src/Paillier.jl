"""
# module Paillier

```jldoctest
julia> pub, priv = generate_paillier_keypair(1024)
julia> c = encrypt(pub, 10)
julia> decrypt(priv, add(pub, c, encrypt(pub, 20)))
30
```

"""
module Paillier

export PrivateKey, PublicKey, Encrypted, encrypt, decrypt
export generate_paillier_keypair, obfuscate

using Primes, Random

include("utilities.jl")
include("cryptosystem.jl")
include("keygeneration.jl")
include("Encoding.jl")
include("encryptedarray.jl")

end
