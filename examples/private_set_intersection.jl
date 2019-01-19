#=
private set intersection - Semi-Honest Case.
Based on the paper "Efficient Private Matching and Set Intersection" by Freedman et all.

Also see https://github.com/encryptogroup/PSI
=#

include("../src/Paillier.jl")
using Main.Paillier
using Test
using Polynomials: poly, coeffs

function generate_polynomial(inputs::Array{Int64})
    # Using http://juliamath.github.io/Polynomials.jl/latest/
    p = poly(inputs)
    return coeffs(p)
end

function run_client(client_input_set, encoding)
    # Client generates keys, and calculates polynomial roots from set inputs
    inputs = collect(client_input_set)
    polynomialcoeffs = generate_polynomial(inputs)
    return encode_and_encrypt(polynomialcoeffs, encoding, 0)
end

function run_server(encrypted_polynomial, server_input_set, encoding)
    # SERVER gets encrypted_polynomial, has own input set:
    function evaluate_encrypted_polynomial_at(x::Int64)
        encres = encode_and_encrypt(0, encoding, 0)
        for power in 0:length(encrypted_polynomial)-1
            a = encrypted_polynomial[power+1]
            encres += a * x^power
        end
        return encres
    end

    serverresults::Array{EncryptedNumber} = []
    for input in collect(server_input_set)
        enc_p_y = evaluate_encrypted_polynomial_at(input)
        enc_y = encode_and_encrypt(input, encoding)
        # This is should be outside of possible set values:
        r = Main.Paillier.n_bit_random_number(64)

        push!(serverresults, r * enc_p_y + enc_y)
    end
    println(typeof(serverresults[1]))
    return EncryptedArray(serverresults)
end

function get_intersection(enc, privatekey)
    intersection::Set{enc.encoding.datatype} = Set()
    for encval in enc
        try
            decrypted = decrypt_and_decode(privatekey, encval)
            #if decrypted < 1e16
                push!(intersection, decrypted)
            #end
        catch InexactError
            # decoding a large random value (indicating an elment not in common)
            continue
        end
    end
    return intersection
end

function run_psi(a, b)
    # INPUTS
    println("Private Set Intersection")
    publickey, privatekey = generate_paillier_keypair()
    datatype = Int64

    client_input_set = Set{datatype}(a)
    server_input_set = Set{datatype}(b)

    # SHARED
    encoding = Encoding(datatype, publickey)

    # CLIENT
    encrypted_polynomial = run_client(client_input_set, encoding)
    println("Sending encrypted polynomial to server now")

    # SERVER
    enc = run_server(encrypted_polynomial, server_input_set, encoding)

    # CLIENT
    println("Client now decrypted set intersection results")
    psi = get_intersection(enc, privatekey)

    @test intersect(client_input_set, server_input_set) == psi
    return psi
end

run_psi([0, 1, 2, 3, 4, 5, 6], [1, 3, 5, 7])

@testset "Private Set Intersection" begin
    KEYSIZES = [128, 256]
    total = @elapsed @testset "client size $asize set" for asize in [5, 10, 100]
        @testset "server size $bsize" for bsize in [5, 10]
            a = rand(Int32, asize)
            b = rand(Int32, bsize)
            run_psi(a, b)
        end
    end
    println("Tests took $(round(total; digits=2)) s")
end
