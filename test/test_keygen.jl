
using Test
using Main.Paillier


@testset "Key Generation" begin
    other_pub, other_priv = generate_paillier_keypair(128)
    KEYSIZES = [128, 256, 512]
    @testset "Keysize $keysize bits" for keysize in KEYSIZES
        pub, priv = generate_paillier_keypair(keysize)

        @test length(string(pub.n, base=2)) > 126
        @test pub.n_sq == pub.n^2
        @test priv.public_key == pub

        a = rand(1:10000000000)
        b = rand(1:10000000000)
        c_a = encrypt(pub, a)
        c_b = encrypt(pub, b)

        @test c_a.public_key == pub
        @test decrypt(priv, c_a) == a
        @test decrypt(priv, c_b) == b
        @test decrypt(priv, c_a + c_b) == a + b
        @test decrypt(priv, c_a + 4) == a + 4
        @test decrypt(priv, 2 * c_a) == 2a
        @test decrypt(priv, 2c_a) == 2a
        @test decrypt(priv, c_a * 2) == 2a

        @test_throws ArgumentError c_a + encrypt(other_pub, a)
        @test_throws ArgumentError decrypt(priv, encrypt(other_pub, a))
    end

end