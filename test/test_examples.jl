macro capture_stdout(ex)
    return quote
        local original_stdout = stdout
        (read_pipe, write_pipe) = redirect_stdout()

        local val = $(esc(ex))

        redirect_stdout(original_stdout)
        close(write_pipe)

        val
    end
end

@testset "Test encoded_numbers.jl example" begin
    @capture_stdout include("../examples/encoded_numbers.jl")
    @test 6000.0 == enc5
end

@testset "Test custom_encodings.jl example" begin
    @capture_stdout include("../examples/custom_encodings.jl")
    @test 6000.0 == enc5
end

@testset "Test private_set_intersection.jl example" begin
    @capture_stdout include("../examples/private_set_intersection.jl")
    include("test_psi_example.jl")
end

@testset "Test raw_cryptosystem.jl example" begin
    @capture_stdout include("../examples/raw_cryptosystem.jl")
    @test 70 == decrypt(priv, c)
end

