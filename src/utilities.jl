
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