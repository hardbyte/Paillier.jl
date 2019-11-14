function overlapping_random_sets(asize, bsize, overlap)
    if asize > bsize
        asize, bsize = bsize, asize
    end
    samples = map(Int64, rand(Int32, asize + bsize))
    bstart = Int(1 + floor(asize * (1 - overlap)))
    return (samples[1:asize], samples[bstart:bstart + bsize - 1])
end

rng = RandomDevice()

@testset "Private Set Intersection Regression" begin
    KEYSIZES = [128, 256, 512]
    @testset "Keysize $keysize" for keysize in KEYSIZES
        @testset "regressions" begin
            run_psi(rng, [1, 2, 3, 4, 5, 6], [1, 3, 5, 7], keysize, Int64)
            run_psi(rng, [0, 1, 2, 3, 4, 5, 6], [1, 3, 5, 7], keysize, Int64)
            run_psi(rng, [0, 1, -2, 3, -4, 5, -6], [1, 3, 5, -7], keysize, Int64)
            run_psi(rng, [0, -1, -2, 3, -4, 5, -6], [1, 3, 5, -7], keysize, Int64)
            run_psi(rng, [0, -1, -2, 3, -4, 5, -6], [-1, 3, 5, -7], keysize, Int64)
            run_psi(rng, [-1, -2, -3, -4, -5, -6], [-1, -3, -5, -7], keysize, Int64)
            run_psi(rng, [-193, 22877, 9991, 27446, 3246], [-193, 22877, 9991, 27446, 3246], keysize, Int64)
            run_psi(rng, [-193, 22877, 22000, 27446, 3246], [-193, 22877, 9991, 27446, 3246], keysize, Int64)
            run_psi(rng,
                [6259, -28346, -4265, -6846, -22361, 23554, -18579, 25132, -12035, -9258],
                [23554, -18579, 25132, -12035, -9258, -29585, -26826, 16883, -2863, 22504, -25746, 12298, -5154, 24574, 31953, -21956, 21564, 4109, -4439, -9133, -20801, -14326, 3750, -2365, 29136, -20365, 11508, -16535, -4472, 22660, 32253, -2968, -7141, 17672, 14392, 2595, -23798, 3685, 29817, -18080, 26321, -3121, 6425, 20294, -21315, -7622, -21143, -30823, -17430, 28611],
                2048,
                Int64)
        end

        @testset "random 50:50 with 1/2 overlap" begin
            a, b = overlapping_random_sets(50, 50, 0.5)
            run_psi(rng, a, b, keysize, Int64)
        end
    end
end

@testset "Private Set Intersection" begin
    KEYSIZES = [256, 512, 1024]
    @testset "Keysize $keysize" for keysize in KEYSIZES
        total = @elapsed @testset "client size $asize set" for asize in [1, 10, 100]
            @testset "server size $bsize" for bsize in [5, 50, 500]
                a, b = overlapping_random_sets(asize, bsize, 0.5)
                run_psi(rng, a, b, keysize, Int64)
            end
        end
        println("Tests for $keysize bit keysize took $(round(total; digits=2)) s")
    end
end