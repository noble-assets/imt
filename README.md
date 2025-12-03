# Incremental Merkle Tree

This is a Go port of the [@zk-kit/imt](https://github.com/zk-kit/zk-kit/tree/main/packages/imt) TypeScript package, originally developed by [Privacy Scaling Explorations](https://pse.dev/).

An Incremental Merkle Tree (IMT) is a data structure used in cryptography and computer science for efficiently verifying the integrity of a large set of data, especially in situations where new data is added over time. It is based on the concept of a Merkle tree, and its key feature is its ability to efficiently update the tree when new data is added or existing data is modified.

In this implementation, the tree is constructed using a fixed depth, and a list of zeroes (one for each level) is used to compute the hash of a node when not all of its children are defined. The number of children for each node can also be specified with the arity parameter.

This package has zero external dependencies.

## Installation

```bash
go get github.com/noble-assets/imt
```

## Usage

```go
package main

import (
    "fmt"

    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/noble-assets/imt"
)

// Define a hash function (e.g., Keccak256)
func keccakHash(children []common.Hash) common.Hash {
    var data []byte
    for _, child := range children {
        data = append(data, child.Bytes()...)
    }
    return crypto.Keccak256Hash(data)
}

func main() {
    depth := 32
    zeroValue := common.Hash{}
    arity := 2

    // Create a new tree
    tree, err := imt.New(keccakHash, depth, zeroValue, arity, nil)
    if err != nil {
        panic(err)
    }

    // Insert leaves
    tree.Insert(common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"))
    tree.Insert(common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002"))
    tree.Insert(common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000003"))

    fmt.Println("Root:", tree.Root().Hex())

    // Update a leaf
    tree.Update(0, common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000004"))

    fmt.Println("Root after update:", tree.Root().Hex())

    // Create and verify a proof
    proof, err := tree.CreateProof(0)
    if err != nil {
        panic(err)
    }

    fmt.Println("Proof valid:", tree.VerifyProof(proof))

    // Delete a leaf (sets it to zero value)
    tree.Delete(0)

    fmt.Println("Root after delete:", tree.Root().Hex())
}
```

## API

### Types

#### `HashFunction[N comparable]`

The hash function used to compute tree nodes.

```go
type HashFunction[N comparable] func(children []N) N
```

#### `MerkleProof[N comparable]`

Contains the necessary parameters to verify that a leaf belongs to the tree.

```go
type MerkleProof[N comparable] struct {
    Root        N     // The root hash of the tree.
    Leaf        N     // The leaf value being proven.
    LeafIndex   int   // The index of the leaf in the tree.
    Siblings    [][]N // Sibling nodes at each level.
    PathIndices []int // Position indices at each level.
}
```

#### `IMT[N comparable]`

The Incremental Merkle Tree structure.

### Functions

#### `New`

Creates a new Incremental Merkle Tree.

```go
func New[N comparable](hash HashFunction[N], depth int, zeroValue N, arity int, leaves []N) (*IMT[N], error)
```

#### `VerifyProof`

Verifies a Merkle proof (standalone function).

```go
func VerifyProof[N comparable](proof *MerkleProof[N], hash HashFunction[N]) bool
```

### Methods

| Method | Description |
|--------|-------------|
| `Root()` | Returns the root of the tree. |
| `Depth()` | Returns the depth of the tree. |
| `Leaves()` | Returns a copy of all leaves in the tree. |
| `Zeroes()` | Returns the list of zero values for each level. |
| `Arity()` | Returns the number of children per node. |
| `Size()` | Returns the number of leaves in the tree. **(not in original)** |
| `IndexOf(leaf)` | Returns the index of a leaf, or -1 if not found. |
| `Insert(leaf)` | Adds a new leaf to the tree. |
| `Update(index, newLeaf)` | Updates a leaf at the given index. |
| `Delete(index)` | Deletes a leaf by setting it to the zero value. |
| `CreateProof(index)` | Creates a Merkle proof for the leaf at the given index. |
| `VerifyProof(proof)` | Verifies a Merkle proof using the tree's hash function. |

## Generics

This implementation uses Go generics with the `comparable` constraint. This means you can use any comparable type as tree nodes, including:

- Primitive types (`string`, `int`, `uint64`, etc.)
- Fixed-size arrays (`[32]byte`, `common.Hash`, etc.)
- Structs with comparable fields

## License

This project is licensed under the MIT License.
