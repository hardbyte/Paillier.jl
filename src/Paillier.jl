"""
# module Paillier

```@meta
CurrentModule = Paillier

DocTestSetup = quote
    using Paillier
    publickey, privatekey = generate_paillier_keypair(256)
end
```

## Basic Usage

Generate a public and private key of given length:

```julia
using Paillier
publickey, privatekey = generate_paillier_keypair(1024);
```

The `publickey` is used for encryption via [`encrypt`](@ref),
and `privatekey` is required for decryption [`decrypt`](@ref).


Encrypted numbers can be added together:

```jldoctest
julia> a = encrypt(publickey, 10);

julia> b = encrypt(publickey, 20);

julia> decrypt(privatekey, a + b)
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
