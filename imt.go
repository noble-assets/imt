// Package imt provides an Incremental Merkle Tree (IMT) implementation.
//
// An IMT is a data structure used in cryptography and computer science for
// efficiently verifying the integrity of a large set of data, especially in
// situations where new data is added over time. It is based on the concept
// of a Merkle tree, and its key feature is its ability to efficiently update
// the tree when new data is added or existing data is modified.
//
// In this implementation, the tree is constructed using a fixed depth, and a
// list of zeroes (one for each level) is used to compute the hash of a node
// when not all of its children are defined. The number of children for each
// node can also be specified with the arity parameter.
package imt

import (
	"errors"
	"math"
	"slices"
)

// HashFunction is the hash function used to compute the tree nodes.
type HashFunction[N comparable] func(children []N) N

// MerkleProof contains the necessary parameters to verify that a leaf indeed
// belongs to a tree. Given the leaf value and its index, it is possible to
// traverse the tree by recalculating the hashes up to the root and using the
// sibling nodes. If the calculated root matches the root in the proof, then
// the leaf belongs to the tree.
type MerkleProof[N comparable] struct {
	Root        N     `json:"root"`        // The root hash of the tree.
	Leaf        N     `json:"leaf"`        // The leaf value being proven.
	LeafIndex   int   `json:"leafIndex"`   // The index of the leaf in the tree.
	Siblings    [][]N `json:"siblings"`    // Sibling nodes at each level.
	PathIndices []int `json:"pathIndices"` // Position indices at each level.
}

// IMT represents an Incremental Merkle Tree.
type IMT[N comparable] struct {
	// The matrix where all the tree nodes are stored. The first index indicates
	// the level of the tree, while the second index represents the node's
	// position within that specific level.
	nodes [][]N

	// A list of zero values calculated during the initialization of the tree.
	// The list contains one value for each level of the tree, and the value for
	// a given level is equal to the hash of the previous level's value.
	// The first value is the zero hash provided by the user.
	// These values are used to calculate the hash of a node in case some of its
	// children are missing.
	zeroes []N

	// The hash function used to compute the tree nodes.
	hash HashFunction[N]

	// The depth of the tree, which is the number of edges from the node to the
	// tree's root node.
	depth int

	// The number of children per node.
	arity int
}

// New initializes the tree with a hash function, the depth, the zero value to
// use for zeroes, and the arity (i.e. the number of children for each node).
// It also takes an optional parameter to initialize the tree with a list of leaves.
func New[N comparable](hash HashFunction[N], depth int, zeroValue N, arity int, leaves []N) (*IMT[N], error) {
	if hash == nil {
		return nil, errors.New("hash function is required")
	}
	if depth <= 0 {
		return nil, errors.New("depth must be positive")
	}
	if arity <= 0 {
		return nil, errors.New("arity must be positive")
	}

	maxLeaves := int(math.Pow(float64(arity), float64(depth)))
	if len(leaves) > maxLeaves {
		return nil, errors.New("the tree cannot contain more than arity^depth leaves")
	}

	// Initialize the attributes.
	imt := &IMT[N]{
		hash:   hash,
		depth:  depth,
		arity:  arity,
		zeroes: make([]N, depth),
		nodes:  make([][]N, depth+1),
	}

	for level := 0; level < depth; level++ {
		imt.zeroes[level] = zeroValue
		imt.nodes[level] = make([]N, 0)
		// There must be a zero value for each tree level (except the root).
		children := make([]N, arity)
		for i := range children {
			children[i] = zeroValue
		}
		zeroValue = hash(children)
	}

	imt.nodes[depth] = make([]N, 0)

	// Initialize the tree with a list of leaves if there are any.
	if len(leaves) > 0 {
		imt.nodes[0] = make([]N, len(leaves))
		copy(imt.nodes[0], leaves)

		for level := 0; level < depth; level++ {
			numParents := int(math.Ceil(float64(len(imt.nodes[level])) / float64(arity)))
			imt.nodes[level+1] = make([]N, numParents)

			for index := 0; index < numParents; index++ {
				position := index * arity
				children := make([]N, arity)

				for i := 0; i < arity; i++ {
					childIdx := position + i
					if childIdx < len(imt.nodes[level]) {
						children[i] = imt.nodes[level][childIdx]
					} else {
						children[i] = imt.zeroes[level]
					}
				}

				imt.nodes[level+1][index] = hash(children)
			}
		}
	} else {
		// If there are no leaves, the default root is the last zero value.
		imt.nodes[depth] = []N{zeroValue}
	}

	return imt, nil
}

// Root returns the root of the tree. This value doesn't need to be stored as
// it is always the first and unique element of the last level of the tree.
func (t *IMT[N]) Root() N {
	if len(t.nodes[t.depth]) == 0 {
		var zero N
		return zero
	}
	return t.nodes[t.depth][0]
}

// Depth returns the depth of the tree, which equals the number of levels - 1.
func (t *IMT[N]) Depth() int {
	return t.depth
}

// Leaves returns the leaves of the tree. They can be retrieved from the first
// level of the tree. The returned value is a copy of the slice and not the
// original object.
func (t *IMT[N]) Leaves() []N {
	result := make([]N, len(t.nodes[0]))
	copy(result, t.nodes[0])
	return result
}

// Zeroes returns the list of zero values calculated during the initialization
// of the tree.
func (t *IMT[N]) Zeroes() []N {
	return t.zeroes
}

// Arity returns the number of children per node.
func (t *IMT[N]) Arity() int {
	return t.arity
}

// Size returns the number of leaves in the tree.
func (t *IMT[N]) Size() int {
	return len(t.nodes[0])
}

// IndexOf returns the index of the first occurrence of a leaf in the tree.
// If the leaf does not exist it returns -1.
func (t *IMT[N]) IndexOf(leaf N) int {
	return slices.Index(t.nodes[0], leaf)
}

// Insert adds a new leaf to the tree. The leaves are inserted incrementally.
// If 'i' is the index of the last leaf, the new one will be inserted at
// position 'i + 1'. Every time a new leaf is inserted, the nodes that separate
// the new leaf from the root of the tree are created or updated if they already
// exist, from bottom to top. When a node has only one child (the left one), its
// value is the hash of that node and the zero value of that level. Otherwise,
// the hash of the children is calculated.
func (t *IMT[N]) Insert(leaf N) error {
	maxLeaves := int(math.Pow(float64(t.arity), float64(t.depth)))
	if len(t.nodes[0]) >= maxLeaves {
		return errors.New("the tree is full")
	}

	node := leaf
	index := len(t.nodes[0])

	for level := 0; level < t.depth; level++ {
		position := index % t.arity
		levelStartIndex := index - position
		levelEndIndex := levelStartIndex + t.arity

		// Expand the slice if needed.
		for len(t.nodes[level]) <= index {
			var zero N
			t.nodes[level] = append(t.nodes[level], zero)
		}
		t.nodes[level][index] = node

		children := make([]N, t.arity)
		for i := levelStartIndex; i < levelEndIndex; i++ {
			childIdx := i - levelStartIndex
			if i < len(t.nodes[level]) {
				children[childIdx] = t.nodes[level][i]
			} else {
				children[childIdx] = t.zeroes[level]
			}
		}

		node = t.hash(children)
		index = index / t.arity
	}

	t.nodes[t.depth][0] = node

	return nil
}

// Delete removes a leaf from the tree. It does not remove the leaf from the
// data structure, but rather it sets the leaf to be deleted to the zero value.
func (t *IMT[N]) Delete(index int) error {
	return t.Update(index, t.zeroes[0])
}

// Update updates a leaf in the tree. It's very similar to the Insert function.
func (t *IMT[N]) Update(index int, newLeaf N) error {
	if index < 0 || index >= len(t.nodes[0]) {
		return errors.New("the leaf does not exist in this tree")
	}

	if t.nodes[0][index] == newLeaf {
		return nil
	}

	node := newLeaf

	for level := 0; level < t.depth; level++ {
		position := index % t.arity
		levelStartIndex := index - position
		levelEndIndex := levelStartIndex + t.arity

		t.nodes[level][index] = node

		children := make([]N, t.arity)
		for i := levelStartIndex; i < levelEndIndex; i++ {
			childIdx := i - levelStartIndex
			if i < len(t.nodes[level]) {
				children[childIdx] = t.nodes[level][i]
			} else {
				children[childIdx] = t.zeroes[level]
			}
		}

		node = t.hash(children)
		index = index / t.arity
	}

	t.nodes[t.depth][0] = node

	return nil
}

// CreateProof creates a MerkleProof for a leaf of the tree. That proof can be
// verified by this tree using the same hash function.
func (t *IMT[N]) CreateProof(index int) (*MerkleProof[N], error) {
	if index < 0 || index >= len(t.nodes[0]) {
		return nil, errors.New("the leaf does not exist in this tree")
	}

	siblings := make([][]N, t.depth)
	pathIndices := make([]int, t.depth)
	leafIndex := index

	for level := 0; level < t.depth; level++ {
		position := index % t.arity
		levelStartIndex := index - position
		levelEndIndex := levelStartIndex + t.arity

		pathIndices[level] = position
		siblings[level] = make([]N, 0, t.arity-1)

		for i := levelStartIndex; i < levelEndIndex; i++ {
			if i != index {
				if i < len(t.nodes[level]) {
					siblings[level] = append(siblings[level], t.nodes[level][i])
				} else {
					siblings[level] = append(siblings[level], t.zeroes[level])
				}
			}
		}

		index = index / t.arity
	}

	return &MerkleProof[N]{
		Root:        t.Root(),
		Leaf:        t.nodes[0][leafIndex],
		LeafIndex:   leafIndex,
		Siblings:    siblings,
		PathIndices: pathIndices,
	}, nil
}

// VerifyProof verifies a MerkleProof to confirm that a leaf indeed belongs to
// a tree. Does not verify that the node belongs to this tree in particular.
// Equivalent to calling the package-level VerifyProof function with this
// tree's hash function.
func (t *IMT[N]) VerifyProof(proof *MerkleProof[N]) bool {
	return VerifyProof(proof, t.hash)
}

// VerifyProof verifies a MerkleProof to confirm that a leaf indeed belongs to
// a tree.
func VerifyProof[N comparable](proof *MerkleProof[N], hash HashFunction[N]) bool {
	if proof == nil {
		return false
	}

	node := proof.Leaf

	for i := 0; i < len(proof.Siblings); i++ {
		children := make([]N, len(proof.Siblings[i]))
		copy(children, proof.Siblings[i])

		children = slices.Insert(children, proof.PathIndices[i], node)

		node = hash(children)
	}

	return proof.Root == node
}
