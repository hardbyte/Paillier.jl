using Test
using Main.Paillier

function test_1d_uint64_array(x::Array{Int64}, publickey, privatekey)
    # closures to capture keys
    encrypt_with_pub(x) = encrypt(publickey, x)
    decrypt_with_priv(x) = decrypt(privatekey, x)

    encrypted = encrypt_with_pub.(x)
    decrypted = decrypt_with_priv.(encrypted)

    return decrypted
end

@testset "Native Array (no encoding)" begin
    for keysize in KEYSIZES
        publickey, privatekey = KEYS[keysize]
        x = [0, 1, 345, 32410, 784564]
        x2 = test_1d_uint64_array(x, publickey, privatekey)
        @test length(x2) == length(x)
        @test all(a == b for (a,b) in zip(x, x2))
    end
end

function test_array(x, keysize)
    @debug size(x)
    publickey, privatekey = KEYS[keysize]
    encoding = Encoding{Float64}(publickey, 64)

    @testset "Array of EncryptedNumbers" begin
        encnum = [encode_and_encrypt(n, encoding) for n in x]
        ea = EncryptedArray(encnum)
        x2 = decrypt_and_decode(privatekey, ea)
        @test all(a == b for (a,b) in zip(x, x2))
    end

    encrypted = encode_and_encrypt(x, encoding)
    encrypted_exp = encode_and_encrypt(x, encoding, -10)
    x2 = decrypt_and_decode(privatekey, encrypted)
    x2 = decrypt_and_decode(privatekey, encrypted_exp)
    @test size(encrypted) == size(x)
    @test size(x2) == size(x)
    @test all(a == b for (a,b) in zip(x, x2))
    doubledciphertext = encrypted * 2
    @test length(doubledciphertext) == length(x)
    @test doubledciphertext.public_key == publickey
    @test 2x == decrypt_and_decode(privatekey, encrypted_exp*2)
    @test 2x == decrypt_and_decode(privatekey, doubledciphertext)
    @test 3x == decrypt_and_decode(privatekey, doubledciphertext + encrypted)
    @test !(doubledciphertext + encrypted).is_obfuscated
    @test obfuscate(doubledciphertext + encrypted).is_obfuscated
    @test 100 .+ x == decrypt_and_decode(privatekey, 100 .+ encrypted)

    @test all(original == decrypt_and_decode(privatekey, encrypted) for (original, encrypted) in zip(x, encrypted))
    @test typeof(encrypted[1]) == EncryptedNumber

    enc_copy = copy(encrypted)
    @test typeof(enc_copy) <: EncryptedArray
    @test typeof(enc_copy[1]) <: EncryptedNumber
    @test decrypt_and_decode(privatekey, enc_copy) == x

    encryptedslice = encrypted[1:3]
    @test typeof(encryptedslice) <: EncryptedArray
    @test decrypt_and_decode(privatekey, encryptedslice) == x[1:3]

    if ndims(encrypted) > 1
        @test decrypt_and_decode(privatekey, encrypted[1, 1]) == x[1, 1]
        @test decrypt_and_decode(privatekey, encrypted[1, 1:3]) == x[1, 1:3]
    end
end

@testset "Multidimensional Paillier Encrypted Arrays" begin
    @testset "Keysize $keysize bits" for keysize in KEYSIZES

        @testset "1D" begin
            x::Array{Float64} = [0.0, 1.0, 345, 3.24e10, 7845.64]
            test_array(x, keysize)

            x2::Array{Int64} = [123, 123, 123, 123, 123]
            test_array(x, keysize)
        end

        @testset "2D" begin
            x = [[0, 1] [345, 32410] [3, 784564]]
            test_array(x, keysize)
        end

        @testset "3D" begin
            x = [
                [1, 1] [34, 3410] [1, 1232];
                [2, 2] [35, 31240] [1, 7844];
                [3, 3] [45, 241] [1, 564];
                ]
            test_array(x, keysize)
        end
    end
end
