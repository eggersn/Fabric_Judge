package verifier

import (
	"log"

	proto "github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric_judge/protos/common"
	kf "github.com/hyperledger/fabric_judge/protos/kafka"
	verdicts "github.com/hyperledger/fabric_judge/verdicts"
)

// Verifier contains the envelopes and metadata of the blocks
type Verifier struct {
	Envelopes         [][]*cb.Envelope
	KafkaMetadata     []*kf.KafkaMetadata
	Identity          string
	PreferredMaxBytes int
	MaxBatchSize      int
	pkPath            string
}

// NewVerifier extracts the envelopes and metadata from the given blocks
func NewVerifier(blocks []*cb.Block, pkPath string, identity string, maxBatchSize int, preferredMaxBytes int) *Verifier {
	verifier := &Verifier{
		Envelopes:         make([][]*cb.Envelope, 0),
		KafkaMetadata:     make([]*kf.KafkaMetadata, 0),
		pkPath:            pkPath,
		Identity:          identity,
		PreferredMaxBytes: preferredMaxBytes,
		MaxBatchSize:      maxBatchSize,
	}

	for _, block := range blocks {
		verifier.getEnvelopesOfBlock(block)
		verifier.getMetadataOfBlock(block)
	}

	return verifier
}

// VerifyKafkaMessages Iterates over all Envelopes (of all blocks) and verifies the Kafka merkleproofs and signatures
func (v *Verifier) VerifyKafkaMessages() []*verdicts.Verdict {
	numberOfBlocks := len(v.Envelopes)
	var err error
	for i, metadata := range v.KafkaMetadata {
		err = ValidateMetadata(metadata, v.pkPath, i == numberOfBlocks)
		if err != nil {
			return evaluateError(err, i == numberOfBlocks)
		}
	}

	for i, blockEnv := range v.Envelopes {
		for tIdx, env := range blockEnv {
			err = VerifyTransaction(env, tIdx, v.pkPath, i == numberOfBlocks)
			if err != nil {
				return evaluateError(err, i == numberOfBlocks)
			}
		}
	}

	return v.verifyKafkaSequence()
}

// VerifyBlockCuttingOfOrderer checks if the orderer followed the specified Block-Cutting algorithm
func (v *Verifier) VerifyBlockCuttingOfOrderer() []*verdicts.Verdict {
	// starting at i = 1, since genesis block is handled seperately
	for i := 1; i < len(v.Envelopes); i++ {
		if v.KafkaMetadata[i].IsConfigMessage {
			// config messages are isolated
			continue
		}

		var blockSize int
		blockSize = 0
		for _, env := range v.Envelopes[i] {
			blockSize += messageSizeBytes(env)
		}

		if blockSize > v.PreferredMaxBytes || len(v.Envelopes[i]) > v.MaxBatchSize {
			if len(v.Envelopes[i]) == 1 {
				// message was isolated as specified
				continue
			} else {
				// otherwise, the orderer cut the block to late
				return []*verdicts.Verdict{verdicts.CreateVerdict("Orderer cut the block too late", v.Identity, 1)}
			}
		}

		if v.KafkaMetadata[i].ReceivedTTCMessage || len(v.Envelopes[i]) == v.MaxBatchSize {
			// we already verified, that the TTC message has the correct kafka sequence number
			// thus the orderer is right, to cut the block at this point
			continue
		}

		// the only remaining possibility for a cut is, if the next envelope would exceed the preferredmaxbytes bound
		if i == len(v.Envelopes)-1 {
			// in this case we are unable to verify, whether the orderer was right to cut the block here
			return nil
		}

		nextEnvSize := messageSizeBytes(v.Envelopes[i+1][0])
		if blockSize+nextEnvSize > v.PreferredMaxBytes {
			// again, the orderer was right to cut here
			continue
		} else if v.KafkaMetadata[i+1].IsConfigMessage {
			// if the orderer sends a config message, the pending block is cut
			continue
		}
		// the orderer could have included the next envelope in this block but did not do so
		return []*verdicts.Verdict{verdicts.CreateVerdict("Orderer cut the block too early", v.Identity, 1)}
	}

	return nil
}

func (v *Verifier) verifyKafkaSequence() []*verdicts.Verdict {
	var kafkaSeqNr, seqNr int64
	kafkaSeqNr = 1

	for i := 0; i < len(v.Envelopes); i++ {
		for _, env := range v.Envelopes[i] {
			seqNr = GetKafkaSeqNrFromEnvelope(env)
			if seqNr != -1 {
				if seqNr != kafkaSeqNr {
					if i == len(v.Envelopes)-1 {
						return []*verdicts.Verdict{verdicts.CreateVerdict("Orderer skipped Kafka messages", v.Identity, 1)}
					}
					return []*verdicts.Verdict{verdicts.CreateVerdict("Orderer skipped Kafka messages", v.Identity, 1), verdicts.CreateVerdict("Peer accepted invalid block without reporting", v.Identity, 1)}
				}
				kafkaSeqNr++
			}
		}
		seqNr = GetKafkaSeqNrFromMetadata(v.KafkaMetadata[i])
		if seqNr != -1 {
			if seqNr != kafkaSeqNr {
				if i == len(v.Envelopes)-1 {
					return []*verdicts.Verdict{verdicts.CreateVerdict("Orderer skipped Kafka messages", v.Identity, 1)}
				}
				return []*verdicts.Verdict{verdicts.CreateVerdict("Orderer skipped Kafka messages", v.Identity, 1), verdicts.CreateVerdict("Peer accepted invalid block without reporting", v.Identity, 1)}
			}
			kafkaSeqNr++
		}
	}

	return nil
}

func (v *Verifier) getEnvelopesOfBlock(block *cb.Block) {
	var err error
	blockEnv := make([]*cb.Envelope, 0)
	for _, data := range block.Data.Data {
		env := new(cb.Envelope)
		err = proto.Unmarshal(data, env)
		if err != nil {
			log.Fatal(err)
		}
		blockEnv = append(blockEnv, env)
	}
	v.Envelopes = append(v.Envelopes, blockEnv)
}

func (v *Verifier) getMetadataOfBlock(block *cb.Block) {
	ordererMetadata := &cb.Metadata{}
	err := proto.Unmarshal(block.Metadata.Metadata[cb.BlockMetadataIndex_ORDERER], ordererMetadata)
	if err != nil {
		log.Fatal(err)
	}

	kafkaMetadata := &kf.KafkaMetadata{}
	err = proto.Unmarshal(ordererMetadata.Value, kafkaMetadata)
	if err != nil {
		log.Fatal(err)
	}

	v.KafkaMetadata = append(v.KafkaMetadata, kafkaMetadata)
}

func evaluateError(err error, lastBlock bool) []*verdicts.Verdict {
	if lastBlock {
		return []*verdicts.Verdict{verdicts.CreateVerdict(err.Error(), "Orderer", 1)}
	}
	return []*verdicts.Verdict{verdicts.CreateVerdict(err.Error(), "Orderer", 1), verdicts.CreateVerdict(err.Error(), "Peer", 2)}
}

func messageSizeBytes(message *cb.Envelope) int {
	return len(message.Payload) + len(message.Signature) + len(message.KafkaPayload.KafkaMerkleProofHeader) + len(message.KafkaPayload.KafkaSignatureHeader) + 1
}
