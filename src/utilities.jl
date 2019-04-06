"""
We create a single module global reference to the RandomDevice.

https://discourse.julialang.org/t/handling-an-optional-rng-parameter/20895/12
"""
const _default_rng = Ref{RandomDevice}()
function __init__()
    _default_rng[] = RandomDevice()
end

"""
When a random number of `n` bits is requested we start a coroutine
to generate random numbers and put them into a `Channel` with buffer
length `DEFAULT_RANDOM_BUFFER`.
"""
DEFAULT_RANDOM_BUFFER = 16

default_rng() = _default_rng[]

compute_random_lt_n(n::BigInt) = compute_random_lt_n(default_rng(), n)
function compute_random_lt_n(rng::AbstractRNG, n::BigInt)
    return rand(rng, big.(1:n))
end

compute_n_bit_random_number(len::Integer) = compute_n_bit_random_number(default_rng(), len)
function compute_n_bit_random_number(rng::AbstractRNG, len::Integer)
    max_n = ( BigInt(1) << len ) - 1
    if len > 2
        min_n = BigInt(1) << (len - 1)
        return rand(rng, min_n:max_n)
    end
    return rand(rng, 1:max_n)
end

function create_producer(rng::AbstractRNG, n::Integer, f)
    function producer(c::Channel)
       while true
           put!(c, f(rng, n))
       end
    end
end

n_bit_producers = Dict{Integer, Channel}()
lt_n_producers = Dict{Integer, Channel}()

"""
When using a lot of n bit random numbers, call this function to start a
Task generating a buffer of them.
"""
init_random_stream(n::Integer, buffer=DEFAULT_RANDOM_BUFFER) = init_random_stream(default_rng(), n, buffer)
function init_random_stream(rng::AbstractRNG, n::Integer, buffer=DEFAULT_RANDOM_BUFFER)
    n_bit_producers[n] = Channel(create_producer(rng, n, compute_n_bit_random_number), csize=buffer)
end

function init_lt_stream(rng::AbstractRNG, n::Integer, buffer=DEFAULT_RANDOM_BUFFER)
    lt_n_producers[n] = Channel(create_producer(rng, n, compute_random_lt_n), csize=buffer)
end

function n_bit_random_channel(n)
    if !haskey(n_bit_producers, n)
        rng = default_rng()
        init_random_stream(rng, n, DEFAULT_RANDOM_BUFFER)
    end
    return n_bit_producers[n]
end

function random_lt_n_channel(n)
    if !haskey(lt_n_producers, n)
        init_lt_stream(default_rng(), n, DEFAULT_RANDOM_BUFFER)
    end
    return lt_n_producers[n]
end

n_bit_random_number(len::Integer) = n_bit_random_number(default_rng(), len)
function n_bit_random_number(rng::AbstractRNG, len::Integer)
    return take!(n_bit_random_channel(len))
end

random_lt_n(n::BigInt) = random_lt_n(default_rng(), n)
function random_lt_n(rng::AbstractRNG, n::BigInt)
    take!(random_lt_n_channel(n))
end

nbit_prime_of_size(n_bits::Integer) = nbit_prime_of_size(default_rng(), n_bits)
function nbit_prime_of_size(rng::AbstractRNG, n_bits::Integer)
    # generate a random nbit number
    r = n_bit_random_number(rng, n_bits)
    return nextprime(r)
end

function match_exponents(a, b)
    if a.exponent > b.exponent
        a = decrease_exponent_to(a, b.exponent)
    elseif a.exponent < b.exponent
        b = decrease_exponent_to(b, a.exponent)
    end
    return a,b
end