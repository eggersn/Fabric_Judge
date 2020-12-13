package judge

import (
	"io/ioutil"
	"log"

	proto "github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric_judge/comparator"
	cb "github.com/hyperledger/fabric_judge/protos/common"
	validator "github.com/hyperledger/fabric_judge/validator"
	"github.com/hyperledger/fabric_judge/verdicts"
)

//export VerifyConsistency
func VerifyConsistency(blockDir1 string, blockDir2 string, identity1 string, identity2 string, kafkaPublicKey string, maxBatchSize int, preferredBlockSize int) {

	println("Reading and parsing received blocks")

	blocks1 := getBlocksFromDir(blockDir1)
	blocks2 := getBlocksFromDir(blockDir2)

	verifier1 := validator.NewVerifier(blocks1, kafkaPublicKey, identity1, maxBatchSize, preferredBlockSize)
	verifier2 := validator.NewVerifier(blocks2, kafkaPublicKey, identity2, maxBatchSize, preferredBlockSize)

	println("Blocks are successfully parsed\n")

	// Verify all merkle proofs, kafka signatures and whether the sequence numbers are incremented sequentially
	// Here, there are two possible verdicts:
	// 1. 	Peer accepts block containing invalid merkle proofs, kafka signatures or inconsistent seq. numbers
	// 		In this case, we blame both orderer and peer
	// 2. 	Inconsistency is only shown in the last block:
	// 		Here we assume, that the peer actually followed the protocol and shut down after receiving an invalid kafka message.

	println("Verifying Merkle-Proofs and signatures of all Kafka messages. Furthermore, we verify that the Kafka sequence numbers are sorted correctly")

	verdict := verifier1.VerifyKafkaMessages()
	evaluateVerdict(verdict)

	verdict = verifier2.VerifyKafkaMessages()
	evaluateVerdict(verdict)

	println("Verification successfully complete\n")

	// Here we can assume, that both peers received the kafka messages in the intended order (because kafka seq. numbers are sorted sequentially)
	// Thus we can now check, if the Kafka Cluster (viewed as a single entity) signed two different messages with the same sequence number
	// In this case, we obviously render a verdict against the Kafka Cluster

	println("Comparing Kafka messages of both blocks to check, if the same sequence number was used on different blocks")

	kafkaComparator := comparator.NewKafkaComparator(verifier1, verifier2)
	verdict = kafkaComparator.CompareKafkaMessages()
	evaluateVerdict(verdict)

	println("No irregularity was found\n")

	// At this point, the only thing left to do is to verify that the orderer cut his blocks according to the given Block-Cutting algorithm

	println("Verifying that the orderer has cut the blocks correctly")

	verdict = verifier1.VerifyBlockCuttingOfOrderer()
	evaluateVerdict(verdict)

	verdict = verifier2.VerifyBlockCuttingOfOrderer()
	evaluateVerdict(verdict)

	println("Orderer cut blocks following the Block-Cutting algorithm")
}

func evaluateVerdict(verdict []*verdicts.Verdict) {
	if verdict != nil {
		for _, v := range verdict {
			log.Println(v.EvaluateVerdict())
		}
		log.Fatal("Inconsistency in blocks is ascertained, exiting...")
	}
}

func getBlocksFromDir(dir string) []*cb.Block {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}

	blocks := make([]*cb.Block, len(files))

	for i, file := range files {
		blocks[i], err = computeBlockFromFile(dir + file.Name())
		if err != nil {
			log.Fatal(err)
		}
	}

	return blocks
}

func computeBlockFromFile(filePath string) (*cb.Block, error) {
	blockData, err := ioutil.ReadFile(filePath)
	if err != nil {
		println("ERROR: Unable to read file: " + filePath)
		return nil, err
	}

	block := new(cb.Block)
	err = proto.Unmarshal(blockData, block)
	if err != nil {
		println("ERROR: Unable to parse block: " + filePath)
	}

	return block, nil
}
