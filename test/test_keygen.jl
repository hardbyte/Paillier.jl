
using Test
using Main.Paillier


@testset "Key Generation" begin
    KEYSIZES = [128, 256, 512]
    @testset "Keysize $keysize bits" for keysize in KEYSIZES
        pub, priv = generate_paillier_keypair(128)

        @test length(string(pub.n, base=2)) > 126
        @test pub.n_sq == pub.n^2

        a = rand(1:10000000000)
        b = rand(1:10000000000)
        c_a = encrypt(pub, a)
        c_b = encrypt(pub, b)
        c_a_b = add(pub, c_a, c_b)

        @test decrypt(priv, c_a) == a
        @test decrypt(priv, c_b) == b
        @test decrypt(priv, c_a_b) == a + b
    end

end