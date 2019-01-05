using Test
using Main.Paillier


function test_encoding_float(x::AbstractFloat, publickey, privatekey, encoding)
    encrypted_number = encode_and_encrypt(x, encoding)
    decoded = decrypt_and_decode(privatekey, encrypted_number)
    @test (decoded - x) < 1e-50
end

function test_adding_encrypted(publickey, privatekey, encoding)
    enc1 = encode_and_encrypt(1.0, encoding)
    enc2 = encode_and_encrypt(2.0, encoding)
    enc3 = enc1 + enc2
    res = decrypt_and_decode(privatekey, enc3)
    @test (res - 3.0) < 1e-50


    enc1 = encode_and_encrypt(445.0, encoding)
    enc2 = encode_and_encrypt(0.1, encoding)

    @test enc1.exponent != enc2.exponent
    enc1_adjusted = decrease_exponent_to(enc1, enc2.exponent)
    @test enc1_adjusted.exponent == enc2.exponent
    @test decrypt_and_decode(privatekey, enc1) == 445.0
    @test decrypt_and_decode(privatekey, enc1_adjusted) == 445.0

    # Manual encoding and encrypting
    encoded_x = encode(445.0, encoding)
    encrypted_1 = encrypt(publickey, encoded_x.value)
    encnum_1 = EncryptedNumber(encrypted_1, encoding, encoded_x.exponent)

    # equivalent to the one step:
    encnum_2 = encode_and_encrypt(0.1, encoding)

    # Can add EncryptedNumbers
    encnum_3 = encnum_1 + encnum_2
    @test 445.1 == decrypt_and_decode(privatekey, encnum_3)

    # Can add EncryptedNumbers and Floats/Integers
    @test 447.1 == decrypt_and_decode(privatekey, encnum_3 + 2.0)
    @test 447.1 == decrypt_and_decode(privatekey, encnum_3 + 2)

end

@testset "Float64 Encoding" begin
    @testset "Keysize $keysize bits" for keysize in [128, 256, 512]
        publickey, privatekey = generate_paillier_keypair(keysize)

        @testset "Encoding with base=$base" for base in [16, 64]
            encoding = Encoding(Float64, publickey, base)
            for x in [-12, 0, 1, 345, 324e10, 78e100]
                test_encoding_float(x, publickey, privatekey, encoding)
            end
            test_adding_encrypted(publickey, privatekey, encoding)
        end
    end
end