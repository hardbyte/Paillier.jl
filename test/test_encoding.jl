using Test
using Main.Paillier


function test_encoding_float(x::AbstractFloat, publickey, privatekey, encoding)
    encrypted_number = encode_and_encrypt(x, encoding)
    decoded = decrypt_and_decode(privatekey, encrypted_number)
    @test (decoded - x) < 1e-50
end


function test_adding_encrypted(publickey, privatekey, encoding::Encoding{T}) where T

    ϵ = BigFloat(2.0)^-precision(T)
    ≊(a, b) = abs(T(a) - T(b)) < ϵ

    # Define a few constants
    one = oneunit(T)
    a = parse(T, "445")
    b = parse(T, "2")
    c = parse(T, "0.1")
    d = parse(T, "1.5e-10")

    enc1 = encode_and_encrypt(one, encoding)
    enc2 = encode_and_encrypt(b, encoding)
    enc3 = enc1 + enc2
    res = decrypt_and_decode(privatekey, enc3)
    @test res ≊ one + b

    enc1 = encode_and_encrypt(a, encoding)
    enc2 = encode_and_encrypt(c, encoding)
    enc3 = encode_and_encrypt(d, encoding)

    @test enc1.exponent > enc2.exponent
    enc1_adjusted = decrease_exponent_to(enc1, enc2.exponent)
    @test enc1_adjusted.exponent == enc2.exponent
    @test decrypt_and_decode(privatekey, enc1) ≊ a
    @test decrypt_and_decode(privatekey, enc1_adjusted) ≊ a

    @test enc2.exponent > enc3.exponent
    @test decrypt_and_decode(privatekey, enc2 + enc3) ≊ c + d

    # Manual encoding and encrypting
    encoded_x = encode(a, encoding)
    encrypted_1 = encrypt(publickey, encoded_x.value)
    encnum_1 = EncryptedNumber(encrypted_1, encoding, encoded_x.exponent)

    # equivalent to the one step:
    encnum_2 = encode_and_encrypt(c, encoding)

    # Can add EncryptedNumbers
    encnum_3 = encnum_1 + encnum_2
    @test (a + c) ≊ decrypt_and_decode(privatekey, encnum_3)

    # Can add EncryptedNumbers and Floats/Integers
    @test (a + c + 2) ≊ decrypt_and_decode(privatekey, encnum_3 + 2.0)
    @test (a + c + 2) ≊ decrypt_and_decode(privatekey, encnum_3 + 2)

end


function test_multipling_encrypted(publickey, privatekey, encoding::Encoding)
    enc1 = encode_and_encrypt(1.0, encoding)
    enc2 = encode_and_encrypt(2.0, encoding)

    # Test multiplication by an integer
    enc3 = 2enc1 + enc2 * 3
    res = decrypt_and_decode(privatekey, enc3)
    @test (res - 8.0) < 1e-50

    # Test multiplication by a float
    res = decrypt_and_decode(privatekey, 0.25enc3)
    @test (res - 2.0) < 1e-50
end

function test_encoding_out_of_range(publickey, privatekey)
    encoding = Encoding{Int64}(publickey, 0)
    encoding2 = Encoding{Int128}(publickey, 0)

    encrypted_number = encode_and_encrypt(BigInt(2)^65, encoding)
    misinterpreted = EncryptedNumber(encrypted_number.encrypted, encoding2, 0)
    decoded = decrypt_and_decode(privatekey, misinterpreted)
    @test decoded == Int128(2)^65
end

@testset "$datatype Encoding" for datatype in [Float32, Float64]
    @testset "Keysize $keysize bits" for keysize in [1024, 2048]
        publickey, privatekey = generate_paillier_keypair(keysize)
        @show test_encoding_out_of_range(publickey, privatekey)
        @testset "Encoding with base=$base" for base in [16, 64]
            encoding = Encoding{datatype}(publickey, base)
            for x in [-12, 0, 1, 345, 324e10, 78e100]
                typed_x = datatype(x)
                if !isinf(typed_x)
                    test_encoding_float(typed_x, publickey, privatekey, encoding)
                else
                    @debug "Skipping test with unrepresentable number"
                end
            end
            test_adding_encrypted(publickey, privatekey, encoding)
            test_multipling_encrypted(publickey, privatekey, encoding)
        end
    end
end