#=
private set intersection - Semi-Honest Case.
Based on the paper "Efficient Private Matching and Set Intersection" by Freedman et all.

Avg time 10000x10000 for 128 bit keysize took 71.73 s
=#

import Paillier
using Test
using Polynomials: Poly, poly, coeffs
using Random: RandomDevice

# Uncomment to show all the debug statements
#ENV["JULIA_DEBUG"] = "all"

"""
Return the coefficients of a polynomial from lowest power to highest.

"""
function generate_polynomial(inputs::Array{BigInt, 1}, n::BigInt)
    # Using http://juliamath.github.io/Polynomials.jl/latest/
    # If the inputs are empty we want a polynomial with no 0 roots, so the constant 1?
    # Note we map to BigInt to avoid the wrap around that is possible with Int64.
    # Optimization idea: Use a numeric datatype that is modulo N
    if length(inputs) == 0
        p = Poly([BigInt(1)])
    else
        # This constructor assumes the form: `(x - a1)(x - a2)...`
        p = poly(BigInt.(inputs))
    end
    # Map the polynomial coefficients onto the Zn field
    return mod.(coeffs(p), n)
end

"""
Helper to map a hash in the range [0, typemax(UInt64)] to
[1, num_buckets]. global for now.
"""
function map_to_bucket(value, num_buckets)
    hash_value = hash(value)
    # Assume hash is discrete uniform random across all of UInt64
    # we multiply by num_buckets/typemax(UInt64) and map back to closest
    # Int.
    return 1 + Int64(round(Rational{BigInt}(hash_value, typemax(UInt64)) * (num_buckets-1)))
end

function allocate_input_to_bucket(input, num_buckets=3)
    buckets::Array{Array{BigInt, 1}} = [[] for i in 1:num_buckets]
    for x in collect(input)
        push!(buckets[map_to_bucket(x, num_buckets)], x)
    end
    return buckets
end

function run_client(client_input_set, public_key, num_buckets, encoding::Paillier.Encoding, exponent::Int64)
    # Client generates keys, and calculates polynomial roots from set inputs
    # Allocate inputs into B buckets
    encoded_input_set = [Paillier.encode(x, encoding, exponent).value for x in client_input_set]
    buckets = allocate_input_to_bucket(encoded_input_set, num_buckets)

    encrypted_polynomials = []
    for bucket_inputs in buckets
        polynomialcoeffs = generate_polynomial(bucket_inputs, public_key.n)
        push!(encrypted_polynomials, [Paillier.encrypt(public_key, coeff) for coeff in polynomialcoeffs])
    end
    return encrypted_polynomials, encoded_input_set
end

"""
The server has their own input data, and gets from the client:
   * an array of encrypted polynomials, and
   * a hash function.

"""
function run_server(rng, encrypted_polynomials, server_input_set, public_key, num_buckets, encoding::Paillier.Encoding, exponent)
    # SERVER gets an Array of encrypted_polynomials, has own input set.

    """
    Evaluate a single encrypted polynomial using horner's rule
    """
    function evaluate_encrypted_polynomial_at(x, encrypted_polynomial)
        encres = 0
        for coeffindx in length(encrypted_polynomial):-1:1
            a = encrypted_polynomial[coeffindx]
            encres = a + x * encres
        end
        return encres
    end
    # TODO just dispatch encode on ConstantExponentEncoding
    encoded_set = [Paillier.encode(x, encoding, exponent).value for x in server_input_set]

    # Buckets' results go into one flat array
    serverresults::Array{Paillier.Encrypted} = []

    # Hash the server's inputs into B buckets
    buckets = allocate_input_to_bucket(encoded_set, num_buckets)

    for bucket_index in eachindex(buckets)
        bucket = buckets[bucket_index]
        encrypted_polynomial = encrypted_polynomials[bucket_index]

        for input in bucket
            enc_p_y = evaluate_encrypted_polynomial_at(input, encrypted_polynomial)

            enc_y = Paillier.encrypt(public_key, input)

            # Multiplying by this r should take the result outside of possible set values:
            r = Paillier.n_bit_random_number(32)

            push!(serverresults, r * enc_p_y + enc_y)
        end
    end

    return serverresults
end

function get_intersection(encoded_input_set, enc, privatekey, e::Paillier.Encoding{T}, exponent::Int64) where T

    intersection::Set{T} = Set()

    for encval in enc
        try
            decrypted = Paillier.decrypt(privatekey, encval)
            if decrypted in encoded_input_set
                decoded = Paillier.decode(decrypted, exponent, e)
                push!(intersection, decoded)
            end
        catch InexactError
            # decoding a large random value (indicating an elment not in common)
            continue
        end
    end
    return intersection
end


run_psi(a, b, keysize) = run_psi(RandomDevice(), a, b, keysize)
function run_psi(rng, a, b, keysize, datatype::DataType, exponent=0)

    publickey, privatekey = Paillier.generate_paillier_keypair(rng, keysize)
    encoding = Paillier.Encoding{datatype}(publickey, 16)
    println("Running PSI with $(length(a)) x $(length(b)) of $(typeof(a[1]))")

    client_input_set = Set{datatype}(a)
    server_input_set = Set{datatype}(b)
    num_buckets = Int64(ceil(log(maximum([10, length(a), length(b)]))))

    # CLIENT
    encrypted_polynomials, encoded_input_set = run_client(client_input_set, publickey, num_buckets, encoding, exponent)
    @debug("Sending encrypted polynomial to server now")

    # SERVER
    enc = run_server(rng, encrypted_polynomials, server_input_set, publickey, num_buckets, encoding, exponent)

    # CLIENT
    @debug("Client now decrypted set intersection results")
    psi = get_intersection(encoded_input_set, enc, privatekey, encoding, exponent)

    # Verify the results
    actual_result = intersect(client_input_set, server_input_set)
    @test length(actual_result) == length(psi)
    if exponent == 0
        @test actual_result == psi
    else
        @test sum(abs.(sort(collect(actual_result)) .- sort(collect(psi)))) < 1e-15
    end
    psi
end

rng = RandomDevice()
intencodingT = Int64
floatencodingT = Float64

@show run_psi(rng, [0, 1, 2, 3, 4, 5, 6], [1, 3, 5, 7], 128, intencodingT)
@show run_psi(rng, [-1.0, 2.0, 3.0, 4.0], [-1.0, 3.0, 5.0, 7.0], 128, floatencodingT)
@show run_psi(rng, [-1.5, 2.2, 3.3, 4.0, 632.243], [-1.5, 3.3, 5.0, 7.0, 632.243], 128, floatencodingT, -12)


