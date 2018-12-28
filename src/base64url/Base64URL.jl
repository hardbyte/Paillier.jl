# Source: https://github.com/felipenoris/JSONWebTokens.jl/blob/master/src/base64url/Base64URL.jl
# This file is a part of Julia. License is MIT: https://julialang.org/license

module Base64URL

export base64url_encode, base64url_decode

# Base64EncodePipe is a pipe-like IO object, which converts into base64 data
# sent to a stream. (You must close the pipe to complete the encode, separate
# from closing the target stream).  We also have a function base64encode(f,
# args...) which works like sprint except that it produces base64-encoded data,
# along with base64encode(args...)  which is equivalent to base64encode(write,
# args...), to return base64 strings.  A Base64DecodePipe object can be used to
# decode base64-encoded data read from a stream , while function base64decode is
# useful for decoding strings

include("buffer.jl")
include("encode.jl")
include("decode.jl")

function base64url_encode(s)
    encoded_str = Base64URL.base64urlencode(s)
    io_out = IOBuffer()
    for c in encoded_str
        if c == '='
            break # removes trailing padding
        end
        write(io_out, c)
    end
    return String(take!(io_out))
end

function base64url_decode(s::AbstractString)
    @assert isascii(s)

    # adds padding back
    r = rem(lastindex(s), 4)
    if r != 0
        for i in 1:(4 - r)
            s *= "="
        end
    end

    return Base64URL.base64urldecode(s)
end

end