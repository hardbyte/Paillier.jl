
rng = RandomDevice()

function n_bit_random_number(len::Number)
    max_n = ( BigInt(1) << len ) - 1
    if len > 2
        min_n = BigInt(1) << (len - 1)
        return rand(min_n:max_n)
    end
    return rand(1:max_n)
end

function nbit_prime_of_size(n_bits)
    # generate a random nbit number
    r = n_bit_random_number(n_bits)
    return nextprime(r)
end

function random_lt_n(n::BigInt)
    return rand(rng, big.(1:n))
end

function match_exponents(a, b)
    if a.exponent > b.exponent
        a = decrease_exponent_to(a, b.exponent)
    elseif a.exponent < b.exponent
        b = decrease_exponent_to(b, a.exponent)
    end
    return a,b
end