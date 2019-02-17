#=
private set intersection - Semi-Honest Case.
Based on the paper "Efficient Private Matching and Set Intersection" by Freedman et all.

Avg time 10000x10000 for 128 bit keysize took 71.73 s
=#

include("../src/Paillier.jl")
using Main.Paillier
using Test
using Polynomials: Poly, poly, coeffs

# Uncomment to show all the debug statements
#ENV["JULIA_DEBUG"] = "all"

struct ConstantExponentEncoding
    encoding::Encoding
    exponent::Integer
end

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

function run_client(client_input_set, public_key, num_buckets, encoding)
    # Client generates keys, and calculates polynomial roots from set inputs
    # Allocate inputs into B buckets
    encoded_input_set = [encode(x, encoding, 0).value for x in client_input_set]
    buckets = allocate_input_to_bucket(encoded_input_set, num_buckets)

    encrypted_polynomials = []
    for bucket_inputs in buckets
        polynomialcoeffs = generate_polynomial(bucket_inputs, public_key.n)
        push!(encrypted_polynomials, [encrypt(public_key, coeff) for coeff in polynomialcoeffs])
    end
    return encrypted_polynomials
end

"""
The server has their own input data, and gets from the client:
   * an array of encrypted polynomials, and
   * a hash function.

"""
function run_server(encrypted_polynomials, server_input_set, public_key, num_buckets, encoding)
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
    encoded_set = [encode(x, encoding, 0).value for x in server_input_set]

    # Buckets' results go into one flat array
    serverresults::Array{Encrypted} = []

    # Hash the server's inputs into B buckets
    buckets = allocate_input_to_bucket(encoded_set, num_buckets)

    for bucket_index in eachindex(buckets)
        bucket = buckets[bucket_index]
        encrypted_polynomial = encrypted_polynomials[bucket_index]

        for input in bucket
            enc_p_y = evaluate_encrypted_polynomial_at(input, encrypted_polynomial)

            enc_y = encrypt(public_key, input)

            # Multiplying by this r should take the result outside of possible set values:
            r = Main.Paillier.n_bit_random_number(32)

            push!(serverresults, r * enc_p_y + enc_y)
        end
    end

    return serverresults
end

function get_intersection(client_input_set, enc, privatekey, encoding)
    intersection::Set{encoding.datatype} = Set()

    for encval in enc
        try
            decrypted = decrypt(privatekey, encval)
            decoded = decode(decrypted, 0, encoding)
            if decoded in client_input_set
                push!(intersection, decoded)
            end
        catch InexactError
            # decoding a large random value (indicating an elment not in common)
            continue
        end
    end
    return intersection
end


function run_psi(a, b, keysize)
    # INPUTS
    #@show a, b

    publickey, privatekey = generate_paillier_keypair(keysize)
    datatype = typeof(a[1])
    encoding = Encoding(datatype, publickey)

    client_input_set = Set{datatype}(a)
    server_input_set = Set{datatype}(b)
    num_buckets = Int64(ceil(log(maximum([10, length(a), length(b)]))))

    # CLIENT
    encrypted_polynomials = run_client(client_input_set, publickey, num_buckets, encoding)
    @debug("Sending encrypted polynomial to server now")

    # SERVER
    enc = run_server(encrypted_polynomials, server_input_set, publickey, num_buckets, encoding)

    # CLIENT
    @debug("Client now decrypted set intersection results")
    psi = get_intersection(client_input_set, enc, privatekey, encoding)

    @test intersect(client_input_set, server_input_set) == psi
    return psi
end

# To compile before we start timing
@show run_psi([0, 1, 2, 3, 4, 5, 6], [1, 3, 5, 7], 128)
@show run_psi([-1.0, 2.0, 3.0, 4.0], [-1.0, 3.0, 5.0, 7.0], 128)


function bench(keysize=512, asize=1000, bsize=1000, repeats=10)
    a, b = overlapping_random_sets(asize, bsize, 0.25)
    total = @elapsed for repeat in 1:repeats
        run_psi(a, b, keysize)
    end
    println("Avg time $(asize)x$(bsize) for $keysize bit keysize took $(round(total/repeats; digits=2)) s")
end


#bench(128, 100, 100)
#bench(128, 1000, 1000)
