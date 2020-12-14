package comparator

import (
	"crypto/sha256"
	"log"
	"reflect"

	cb "github.com/hyperledger/fabric_judge/protos/common"
	kf "github.com/hyperledger/fabric_judge/protos/kafka"
	validator "github.com/hyperledger/fabric_judge/validator"
	verdicts "github.com/hyperledger/fabric_judge/verdicts"
)

// UnwrappedLedgerInfo contains the unwrapped envelopes and the Kafka metadata
type UnwrappedLedgerInfo struct {
	Envelopes []*cb.Envelope
	Metadata  []*kf.KafkaMetadata
	Identity  string
}

// KafkaComparator contains two instances of UnwrappedLedgerInfo which allows us to compare the Kafka messages
type KafkaComparator struct {
	ledgerInfo1 *UnwrappedLedgerInfo
	ledgerInfo2 *UnwrappedLedgerInfo
}

// NewKafkaComparator creates a new instance of KafkaComparator
func NewKafkaComparator(verifier1 *validator.Verifier, verifier2 *validator.Verifier) *KafkaComparator {
	return &KafkaComparator{
		ledgerInfo1: computeLedgerInfoFromVerifier(verifier1),
		ledgerInfo2: computeLedgerInfoFromVerifier(verifier2),
	}
}

// CompareKafkaMessages verifies, that the Kafka Cluster did not add the same sequence number to two different Kafka messages
func (comp *KafkaComparator) CompareKafkaMessages() []*verdicts.Verdict {
	// The number of envelopes can vary, in case the orderer service did not follow the Block-Cutting algorithm
	// Note that we can compare the kafka messages this way, because:
	// 1. we already know that the kafka messages are ordered sequentially (always incremented by one)
	// 2. if we compare an altered ledger with a correct one, we know after this first step, that all envelopes are equal,
	// Thus for each time, there comes a TTC-message for the correct ledger, there must be one for the altered one as well.
	// Therefore, only the TTC-messages can be altered, which is checked in the second step
	minNumberOfEnvelopes := len(comp.ledgerInfo1.Envelopes)
	if minNumberOfEnvelopes > len(comp.ledgerInfo2.Envelopes) {
		minNumberOfEnvelopes = len(comp.ledgerInfo2.Envelopes)
	}

	for i := 0; i < minNumberOfEnvelopes; i++ {
		hash1 := computeHashOfEnvelope(comp.ledgerInfo1.Envelopes[i])
		hash2 := computeHashOfEnvelope(comp.ledgerInfo2.Envelopes[i])
		if !reflect.DeepEqual(hash1, hash2) {
			return []*verdicts.Verdict{verdicts.CreateVerdict("Kafka signed two different messages with the same sequence number", "Kafka Cluster", 0)}
		}
	}

	// Check if TTC-messages were altered
	// Here, we already have the minimum block height computed by the python script
	for i := 0; i < len(comp.ledgerInfo1.Metadata); i++ {
		if comp.ledgerInfo1.Metadata[i].ReceivedTTCMessage && comp.ledgerInfo2.Metadata[i].ReceivedTTCMessage {
			hash1 := computeHashOfBytes(comp.ledgerInfo1.Metadata[i].TTCPayload.ConsumerMessageBytes)
			hash2 := computeHashOfBytes(comp.ledgerInfo2.Metadata[i].TTCPayload.ConsumerMessageBytes)
			if !reflect.DeepEqual(hash1, hash2) {
				return []*verdicts.Verdict{verdicts.CreateVerdict("Kafka signed two different ttc-messages with the same sequence number", "Kafka Cluster", 0)}
			}
		} else if !comp.ledgerInfo1.Metadata[i].ReceivedTTCMessage && !comp.ledgerInfo2.Metadata[i].ReceivedTTCMessage {
			continue
		} else {
			// such an error would already be spotted in the comparison of the envelopes
			log.Fatal("ERROR: Impossible If-Branch")
		}
	}

	//at this point, we have no more messages to compare
	return nil
}

func computeLedgerInfoFromVerifier(verifier *validator.Verifier) *UnwrappedLedgerInfo {
	size := 0
	for i := 0; i < len(verifier.Envelopes); i++ {
		size += len(verifier.Envelopes[i])
	}

	ledgerInfo := new(UnwrappedLedgerInfo)
	ledgerInfo.Envelopes = make([]*cb.Envelope, size)
	ledgerInfo.Metadata = verifier.KafkaMetadata
	ledgerInfo.Identity = verifier.Identity

	height := 0
	for i := 0; i < len(verifier.Envelopes); i++ {
		for _, env := range verifier.Envelopes[i] {
			ledgerInfo.Envelopes[height] = env
			height++
		}
	}

	return ledgerInfo
}

func computeHashOfEnvelope(env *cb.Envelope) []byte {
	h := sha256.New()
	h.Write(env.Payload)
	h.Write(env.Signature)
	return h.Sum(nil)
}

func computeHashOfBytes(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}
