
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


function encode(scalar::Float64, encoding::Encoding)
    max_num = BigInt(floor(encoding.public_key.n / 3))

    mantisa_digits = 53

    # Precision calculation
    bin_flt_exp = frexp(scalar)[2]
    bin_lsb_exponent = bin_flt_exp - mantisa_digits
    exponent = Int64(floor(bin_lsb_exponent/log2(encoding.base)))

    # Todo consider if precision is given or part of the Encoding?
    #if max_exponent
    #exponent = floor(log(encoding.base, precision))

    int_rep = BigInt(round(BigFloat(scalar) * encoding.base^Float64(-exponent)))

    if abs(int_rep) >= max_num
        throw(DomainError("Attempt to encode unrepresentable number"))
    end

    return mod(int_rep, encoding.public_key.n), exponent
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

