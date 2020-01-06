using Documenter
using Paillier

makedocs(
    sitename = "Paillier.jl",
    authors = "Brian Thorne",
    format = Documenter.HTML(
        prettyurls = get(ENV, "CI", nothing) == "true"
    ),
    modules = [Paillier]
)

# Documenter can also automatically deploy documentation to gh-pages.
# See "Hosting Documentation" and deploydocs() in the Documenter manual
# for more information.
deploydocs(
    repo = "github.com/hardbyte/Paillier.jl"
)
