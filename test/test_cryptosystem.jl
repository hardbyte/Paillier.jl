
using Test
using Main.Paillier


@testset "Cryptosystem" begin
    other_pub, other_priv = generate_paillier_keypair(128)
    KEYSIZES = [128, 256, 512, 1024]
    @testset "Keysize $keysize bits" for keysize in KEYSIZES
        pub, priv = generate_paillier_keypair(keysize)

        @test length(string(pub.n, base=2)) > 126
        @test pub.n_sq == pub.n^2
        @test priv.public_key == pub

        @testset "Encrypt decrypt small integers" begin
            @test decrypt(priv, encrypt(pub, -0)) == 0
            @test decrypt(priv, encrypt(pub, 0)) == 0
            for i in 1:10
                @test decrypt(priv, encrypt(pub, i)) == i
            end
        end

        a = rand(1:10000000000)
        b = rand(1:10000000000)
        c_a = encrypt(pub, a)
        c_b = encrypt(pub, b)

        @test c_a.public_key == pub
        @test decrypt(priv, c_a) == a
        @test decrypt(priv, c_b) == b
        @test decrypt(priv, obfuscate(c_a + c_b)) == a + b
        @test decrypt(priv, c_a + c_b) == a + b
        @test decrypt(priv, c_a + 4) == a + 4
        @test decrypt(priv, 2 * c_a) == 2a
        @test decrypt(priv, 2c_a) == 2a
        @test decrypt(priv, c_a * 2) == 2a

        @test_throws ArgumentError c_a + encrypt(other_pub, a)
        @test_throws ArgumentError decrypt(priv, encrypt(other_pub, a))

        @testset "Test encrypting negative numbers" begin
            @test_throws DomainError encrypt(pub, -1)
            @test_throws DomainError encrypt(pub, -10)

        end

        @testset "Test encrypting large numbers" begin
            max_int = BigInt(pub.n - 1)
            @test decrypt(priv, encrypt(pub, max_int)) == max_int
            @test decrypt(priv, 0 + encrypt(pub, max_int)) == max_int
            @test decrypt(priv, obfuscate(0 + encrypt(pub, max_int))) == max_int

            # test wrap around
            @test decrypt(priv, 2 + encrypt(pub, max_int)) == 1
            @test decrypt(priv, obfuscate(2 + encrypt(pub, max_int))) == 1

            for divisor in vcat(2:10, map(abs, rand(Int64, 10)))
                x = BigInt(round((max_int-1)/divisor))
                for i in rand(1:(divisor-1), 10)
                    @test decrypt(priv, i * encrypt(pub, x)) == i * x
                end
            end

            # A number that should be able to be doubled 100's of times
            x = BigInt(round((max_int-1)/rand(1000:100000)))
            encx = encrypt(pub, x)
            for i in 1:1000
                encx = 1 * encx
                @test decrypt(priv, encx) == x
            end
            encx = encrypt(pub, 2)
            for i in 2:log10(keysize)
                encx = 2 * encx
                @test decrypt(priv, encx) == 2^i
            end
        end
    end
end