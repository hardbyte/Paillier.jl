#=
private_set_intersection - Semi-Honest Case.
=#

include("../src/Paillier.jl")
using Main.Paillier

using Polynomials


println("Private Set Intersection")
publickey, privatekey = generate_paillier_keypair()
encoding = Encoding(Float32, publickey,  64)

function generate_polynomial(inputs::Array{Int64})
    # http://juliamath.github.io/Polynomials.jl/latest/
    p = poly(inputs)
    return coeffs(p)
end

function run_client()
    # Client generates keys, and calculates polynomial roots from set inputs
    # Could use `Set` type but will be easier to convert to array anyway
    client_input_set = Set([0, 1,2,3,4,6])
    inputs = collect(client_input_set)
    polynomialcoeffs = generate_polynomial(inputs)
    return encode_and_encrypt(polynomialcoeffs, encoding)
end

function run_server(encrypted_polynomial)
    # SERVER gets encrypted_polynomial, has own input set:
    server_input_set = Set([0, 3,4,6,7,8,9])

    function evaluate_encrypted_polynomial_at(x::Int64)
        encres = encode_and_encrypt(0.0, encoding)
        for power in 0:length(encrypted_polynomial)-1
            a = encrypted_polynomial[power+1]
            encres += a * x^power
        end
        return encres
    end

    serverresults = []
    for input in collect(server_input_set)
        enc_p_y = evaluate_encrypted_polynomial_at(input)
        enc_y = encode_and_encrypt(input, encoding)
        r = Main.Paillier.n_bit_random_number(64)

        push!(serverresults, r * enc_p_y + enc_y)
    end
    return serverresults
end


encrypted_polynomial = run_client()

println("Sending encrypted_polynomial to server now")
enc = run_server(encrypted_polynomial)

for encval in enc
    decrypted = decrypt_and_decode(privatekey, encval)
    if decrypted < 1e16
        println(decrypted)
    end
end
