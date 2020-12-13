package main

import (
	"log"
	"os"
	"strconv"

	"github.com/hyperledger/fabric_judge/judge"
)

func main() {
	// input arguments:
	// blockDir1 string, blockDir2 string, identity1 string, identity2 string, kafkaPublicKey string, maxBatchSize int, preferredBlockSize int
	args := os.Args[1:]

	maxBatchSize, err := strconv.Atoi(args[5])
	if err != nil {
		log.Panicf("Invalid maxBatchSize")
	}

	preferredMaxBytes, err := strconv.Atoi(args[6])
	if err != nil {
		log.Panicf("Invalid maxBatchSize")
	}

	judge.VerifyConsistency(args[0]+"/", args[1]+"/", args[2], args[3], args[4], maxBatchSize, preferredMaxBytes)
}

// func main() {
// 	dir1 := "/home/simon/go/src/github.com/hyperledger/fabric-samples/first-network/scripts/judge/data/peer0.org1.example.com_blocks/blocks/"
// 	dir2 := "/home/simon/go/src/github.com/hyperledger/fabric-samples/first-network/scripts/judge/data/peer1.org1.example.com_blocks/blocks/"
// 	pkPath := "/home/simon/go/src/github.com/hyperledger/fabric-samples/first-network/KafkaKeyPair/public.key"
// 	judge.VerifyConsistency(dir1, dir2, "peer0.org1", "peer1.org1", pkPath, 10, 512000)
// }
