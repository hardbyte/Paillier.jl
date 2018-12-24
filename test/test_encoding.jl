using Test
using Main.Paillier

function test_encoding_float(x::Float64, keysize)
    publickey, privatekey = generate_paillier_keypair(keysize)
    encoding = Encoding(Float64, publickey, 16)
    encoded_x, exponent = encode(x, encoding)
    encrypted = encrypt(publickey, encoded_x)
    decrypted = decrypt(privatekey, encrypted)
    decoded = decode(decrypted, exponent, encoding)
    return decoded
end

@testset "Float64 Encoding" begin
    for keysize in [128, 256, 512]
        for x in [-12, 0, 1, 345, 324e10, 78e100]
            x2 = test_encoding_float(x, keysize)
            #println(x2)
            @test (x - x2) < 1e-50
        end
    end
end