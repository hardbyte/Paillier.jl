#=
private_set_intersection - Semi-Honest Case.
=#

include("../src/Paillier.jl")
using Main.Paillier

using Polynomials: poly, coeffs

function generate_polynomial(inputs::Array{Int64})
    # Using http://juliamath.github.io/Polynomials.jl/latest/
    p = poly(inputs)
    return coeffs(p)
end

function run_client(client_input_set)
    # Client generates keys, and calculates polynomial roots from set inputs
    inputs = collect(client_input_set)
    polynomialcoeffs = generate_polynomial(inputs)
    return encode_and_encrypt(polynomialcoeffs, encoding, 0)
end

function run_server(encrypted_polynomial, server_input_set)
    # SERVER gets encrypted_polynomial, has own input set:
    function evaluate_encrypted_polynomial_at(x::Int64)
        encres = encode_and_encrypt(0, encoding, 0)
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
        # This is should be outside of possible set values:
        r = Main.Paillier.n_bit_random_number(64)

        push!(serverresults, r * enc_p_y + enc_y)
    end
    return serverresults
end

function get_intersection(enc)
    intersection::Set{datatype} = Set()
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

# INPUTS
println("Private Set Intersection")
publickey, privatekey = generate_paillier_keypair()
datatype = Int64

client_input_set = Set{datatype}([0, 1, 2, 3, 4, 6])
server_input_set = Set{datatype}([0, 3, 4, 6, 7, 8, 9])

# SHARED
encoding = Encoding(datatype, publickey)

# CLIENT
encrypted_polynomial = run_client(client_input_set)
println("Sending encrypted polynomial to server now")

# SERVER
enc = run_server(encrypted_polynomial, server_input_set)

# CLIENT
println("Client now decrypted set intersection results")
psi = get_intersection(enc)

println(psi)
println(intersect(client_input_set, server_input_set))
