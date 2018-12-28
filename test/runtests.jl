using Test

include("../src/Paillier.jl")
using Main.Paillier


include("test_cryptosystem.jl")
include("test_encoding.jl")
include("test_encryptedarray.jl")
include("test_base64url.jl")

