/*
Copyright IBM Corp. 2016 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"

	"github.com/jamesruan/sodium"
)

//Proof contains information of MerkleProof of Kafka Cluster
type Proof struct {
	RootHash  []byte
	ProofSet  [][]byte
	LeafIndex int
	LeafSize  int
	HashAlg   string
}

// GetProofFromBytes converts bytes into a Merkle Proof struct. The byte array should be formed as follows
//hash length (int) | proofSet Size (int) | leafIndex (int) | leafSize (int) | rootHash (byte[]) | proofSet (byte[][]) | hashAlgorithm (String)
//ref: https://github.com/mar-be/merkle_tree/blob/master/src/main/java/de/marvin/merkletree/Proof.java
func GetProofFromBytes(encProof []byte) (proof Proof) {
	hashLength := int(binary.BigEndian.Uint32(encProof[0:4]))
	proofSetSize := int(binary.BigEndian.Uint32(encProof[4:8]))
	proof.LeafIndex = int(binary.BigEndian.Uint32(encProof[8:12]))
	proof.LeafSize = int(binary.BigEndian.Uint32(encProof[12:16]))
	proof.RootHash = encProof[16 : 16+hashLength]
	proof.ProofSet = make([][]byte, proofSetSize)
	for i := 0; i < proofSetSize; i++ {
		proof.ProofSet[i] = encProof[16+hashLength*(i+1) : 16+hashLength*(i+2)]
	}
	proof.HashAlg = string(encProof[16+hashLength*(proofSetSize+1):])
	if proof.HashAlg != "SHA-256" {
		fmt.Println("!!§!! Unsupported Hashing Algorithm is used !!§!!")
	}
	return
}

// VerifyProof verifies that the message is part of the kafka message stream
func (proof Proof) VerifyProof(data []byte) bool {
	index := proof.LeafIndex
	leafSize := proof.LeafSize

	h := sha256.New()
	h.Write(data)

	for i := 0; i < len(proof.ProofSet); i++ {
		if index == leafSize-1 || index%2 == 1 {
			data = h.Sum(nil)
			h.Reset()
			h.Write(proof.ProofSet[i])
			h.Write(data)
		} else {
			data = h.Sum(nil)
			h.Reset()
			h.Write(data)
			h.Write(proof.ProofSet[i])
		}
		leafSize = leafSize/2 + leafSize%2
		index = index / 2
	}

	data = h.Sum(nil)

	return reflect.DeepEqual(data, proof.RootHash)
}

//VerifiySignature verifies that Kafka actually signed the massage
func (proof Proof) VerifySignature(sigBytes []byte) error {
	pk_file, _ := os.Open("/etc/KafkaKeyPair/public.key")
	pk_bytes, _ := ioutil.ReadAll(pk_file)

	signature := sodium.Signature{sodium.Bytes(sigBytes)}
	pk := sodium.SignPublicKey{sodium.Bytes(pk_bytes)}
	data := sodium.Bytes(proof.RootHash)

	err := data.SignVerifyDetached(signature, pk)

	return err
}

//VerifiySignature verifies that Kafka actually signed the massage
func (proof Proof) VerifySignatureWithPath(sigBytes []byte, pkPath string) error {
	pk_file, _ := os.Open(pkPath)
	pk_bytes, _ := ioutil.ReadAll(pk_file)

	signature := sodium.Signature{sodium.Bytes(sigBytes)}
	pk := sodium.SignPublicKey{sodium.Bytes(pk_bytes)}
	data := sodium.Bytes(proof.RootHash)

	err := data.SignVerifyDetached(signature, pk)

	return err
}
