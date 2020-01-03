"""
We create a single module global reference to the RandomDevice.

https://discourse.julialang.org/t/handling-an-optional-rng-parameter/20895/12
"""
const _default_rng = Ref{RandomDevice}()
function __init__()
    _default_rng[] = RandomDevice()
end

default_rng() = _default_rng[]

n_bit_random_number(len::Integer) = n_bit_random_number(default_rng(), len)
function n_bit_random_number(rng::AbstractRNG, len::Integer)
    max_n = ( BigInt(1) << len ) - 1
    if len > 2
        min_n = BigInt(1) << (len - 1)
        return rand(rng, min_n:max_n)
    end
    return rand(rng, 1:max_n)
end

nbit_prime_of_size(n_bits::Integer) = nbit_prime_of_size(default_rng(), n_bits)
function nbit_prime_of_size(rng::AbstractRNG, n_bits::Integer)
    # generate a random nbit number
    r = n_bit_random_number(rng, n_bits)
    return nextprime(r)
end

random_lt_n(n::BigInt) = random_lt_n(default_rng(), n)
function random_lt_n(rng::AbstractRNG, n::BigInt)
    return rand(rng, big.(1:n))
end

function match_exponents(a, b)
    if a.exponent > b.exponent
        a = decrease_exponent_to(a, b.exponent)
    elseif a.exponent < b.exponent
        b = decrease_exponent_to(b, a.exponent)
    end
    return a, b
end
