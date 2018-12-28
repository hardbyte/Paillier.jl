
# Sketch of encoding floats for the Paillier cryptosystem.
#include("./Paillier.jl")

#using .Paillier

export Encoding, encode, decode

"""
A datatype for describing encoding works.

julia> encoding = Encoding(Float64, 16)

## ?
Use a `do` block to set encoding?

julia> setencoding(encoding) do
    encoded_encrypt(a)
end
"""
struct Encoding
    datatype::DataType
    public_key::PublicKey
    base::Int64
end

function intrep(scalar::BigFloat, n::BigInt, base::Int64, exponent::Int64)::BigInt
    int_rep = BigInt(round(scalar * base^Float64(-exponent)))
    max_num = BigInt(floor(n / 3))
    if abs(int_rep) >= max_num
        throw(DomainError("Attempt to encode unrepresentable number"))
    end
    return mod(int_rep, n)
end

function encode(scalar::Float64, encoding::Encoding)
    mantisa_digits = 53

    # Precision calculation
    bin_flt_exp = frexp(scalar)[2]
    bin_lsb_exponent = bin_flt_exp - mantisa_digits
    exponent = Int64(floor(bin_lsb_exponent/log2(encoding.base)))

    int_rep = intrep(BigFloat(scalar), encoding.public_key.n, encoding.base, exponent)

    return int_rep, exponent
end

function decode(encoded::BigInt, exponent::Int, encoding::Encoding)
    max_num = BigInt(floor(encoding.public_key.n / 3))
    if encoded >= encoding.public_key.n
        throw(ArgumentError("Attempt to decode corrupted ciphertext"))
    elseif encoded <= max_num
        # positive
        mantissa = encoded
    elseif encoded >= encoding.public_key.n - max_num
        # negative
        mantissa = encoded - encoding.public_key.n
    else
        throw(ArgumentError("Overflow detected"))
    end
    # convert to BigFloat
    return mantissa * encoding.base^Float64(exponent)

end

