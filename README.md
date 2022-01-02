## gomorph

**gomorph** provides implementations of Homomorphic Crypto in pure Go.

Currently `gomorph` provides the following schemes :

  - The Paillier Scheme ([reference](https://www.wikiwand.com/en/Paillier_cryptosystem)).

The following are a slow work in progress :

  - The Fan-Vercauteren scheme ([reference](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.400.6346&rep=rep1&type=pdf))

## Usage

You can fetch the latest release using `go get` :

```sh

$ go get -u github.com/actuallyachraf/gomorph@0.2.

```

Code examples can be found in `examples/` you can run the examples using `go run` :

```sh

$ go run examples/paillier.go

```

## Developement

You can contribute by following the usual process (fork, make changes and open a PR) see [CONTRIBUTING.md](CONTRIBUTING.md)
for more details.

As a general guideline adhere to the [conventional commits](https://conventionalcommits.org/) guidelines for commit messages.

For general Go code we try to stay within the [Effective Go](https://go.dev/doc/effective_go) recommendations with unit tests
for all external and internal code.

`go imports` and `go fmt` should be used on all Go files in the codebase.

Aoid using third-party libraries to keep track of any unintended side-effects.

## For citations

```
@MISC {Gomoprh,
  author       = "Achraf B",
  title        = "Go-morph - a pure Golang implementation of the Paillier cryptosystem",
  howpublished = "https://github.com/actuallyachraf/gomorph",
  month        = "March",
  year         = "2019",
}
```
