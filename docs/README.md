## Build the docs locally:

```
julia -e 'using Pkg; Pkg.activate(); push!(LOAD_PATH, pwd());'
julia --project=docs/ -e 'using Pkg; Pkg.activate();  push!(LOAD_PATH,pwd());'

julia --project=docs/ -e 'using Pkg; Pkg.develop(PackageSpec(path=pwd())); Pkg.instantiate();'
julia --project=docs/ --color=yes docs/make.jl
```

Find the docs here: https://hardbyte.github.io/Paillier.jl/stable/
