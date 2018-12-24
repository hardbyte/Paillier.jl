**Paillier.jl** is a [Julia](http://julialang.org/) package implementing the basics of the *Paillier* 
partially homomorphic cryptosystem.

Based off the [sketch](https://github.com/snipsco/paillier-libraries-benchmarks/tree/master/julia-sketch) 
written by [Morten Dahl](https://github.com/mortendahl) at [Snips](https://snips.ai), and the 
[python-paillier](https://github.com/n1analytics/python-paillier) library written by 
[N1 Analytics](https://www.n1analytics.com).

The homomorphic properties of the paillier crypto system are:

* Encrypted numbers can be multiplied by a non encrypted scalar.
* Encrypted numbers can be added together.

## Quick Example

```julia
julia> using Paillier
julia> pub, priv = generate_paillier_keypair(1024)
julia> a = encrypt(pub, 10)
julia> b = encrypt(pub, 50)
julia> decrypt(priv, a)
10
julia> c = 2a + b;
julia> typeof(c)
EncryptedNumber
julia> decrypt(priv, c)
70
```

## More Examples

A number of examples can (eventually) be found [here](./examples), for now just some 
[benchmarking](http://nbviewer.ipython.org/github/hardbyte/Paillier.jl/blob/master/examples/benchmarking.ipynb).
