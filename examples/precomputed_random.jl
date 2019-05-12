"""
A test script that requires the use of a lot of random numbers.

Launches a few worker tasks that each obfuscate a vector of encrypted numbers.

"""

import Paillier
import Random

const jobs = Channel{Tuple}(32);
const results = Channel{Tuple}(32);

println("Generating keypair")
pub, priv = Paillier.generate_paillier_keypair(1024)
encoding = Paillier.Encoding(Float64, pub)

println("Encrypting source numbers")
array_size = 500
x = Random.rand(array_size)
enc_x = Paillier.encode_and_encrypt(x, encoding)

BUFFER_STREAM_SIZE = 100000
Paillier.init_random_stream(pub.n, BUFFER_STREAM_SIZE)

function enc_add_1(enc_x)
    return Paillier.obfuscate(enc_x .+ 1.0)
end

function do_work()
    println("Worker started")
    for (job_id, enc_x) in jobs
        println("Computing job $job_id")
        exec_time = @elapsed res = enc_add_1(enc_x)
        put!(results, (job_id, exec_time, res))
    end
end

function make_work(n)
    for i in 1:n
        put!(jobs, (i, enc_x))
    end
end

n = 10
println("feed the jobs channel with $n jobs")
@async make_work(n)

println("Scheduling the workers")
workers = 2
for i in 1:workers
    @async do_work()
end

total_time = @elapsed while n > 0
    # print results
    job_id, exec_time, enc_res = take!(results)
    @assert x .+ 1.0 == Paillier.decrypt_and_decode(priv, enc_res)
    println("#$job_id finished in $(round(exec_time; digits=2)) seconds")
    global n = n - 1
end

println("Done in $(round(total_time; digits=2)) seconds")
