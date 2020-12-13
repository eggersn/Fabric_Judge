package verifier

import (
	"encoding/binary"
	"fmt"

	proto "github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric_judge/protos/common"
	kf "github.com/hyperledger/fabric_judge/protos/kafka"
)

// ValidateMetadata checks the merkle proof and signature, in case the block contains a TTC message
func ValidateMetadata(kafkaMetadata *kf.KafkaMetadata, pkPath string, lastBlock bool) error {
	if kafkaMetadata.ReceivedTTCMessage {
		proof := GetProofFromBytes(kafkaMetadata.KafkaPayload.KafkaMerkleProofHeader)

		//Verify Merkle Proof
		if !proof.VerifyProof(kafkaMetadata.KafkaPayload.ConsumerMessageBytes) {
			if !lastBlock {
				return fmt.Errorf("Peer should not have accepted faulty block (merkle proof of metadata is invalid). Furthermore, the orderer should not have forwarded this block in the first case")
			} else {
				return fmt.Errorf("Orderer forwarded faulty block (merkle proof of metadata is invalid)")
			}
		}

		//Verify Signature
		if proof.VerifySignatureWithPath(kafkaMetadata.KafkaPayload.KafkaSignatureHeader, pkPath) != nil {
			if !lastBlock {
				return fmt.Errorf("Peer should not have accepted faulty block (metadata signature is invalid). Furthermore, the orderer should not have forwarded this block in the first case")
			} else {
				return fmt.Errorf("Orderer forwarded faulty block (metadata signature is invalid)")
			}
		}
	}
	return nil
}

// VerifyTransaction checks the validity of the envelopes Kafka merkle proofs and signatures
func VerifyTransaction(env *cb.Envelope, tIdx int, pkPath string, lastBlock bool) error {

	if env.KafkaPayload != nil {
		proof := GetProofFromBytes(env.KafkaPayload.KafkaMerkleProofHeader)

		// Rebuild Kafkas Signed Data
		/*
		* In the Following we describe, how we rebuild the signed data:
		*
		* Kafka signs the ConsumerMessages Payload, which is a marshaled KafkaMessage.
		* The Orderer can cast this KafkaMessage to a KafkaMessageRegular which contains the Payload of the marshaled Envelope and other fields.
		* To avoid redundancy, we marshal the sent Envelope (!! without the newly added KafkaPayload !!) to regain the Payload of the KafkaMessageRegular.
		 */
		oldEnv := &cb.Envelope{
			Payload:              env.Payload,
			Signature:            env.Signature,
			XXX_NoUnkeyedLiteral: env.XXX_NoUnkeyedLiteral,
			XXX_unrecognized:     env.XXX_unrecognized,
			XXX_sizecache:        env.XXX_sizecache,
		}

		regMessagePayload, _ := proto.Marshal(oldEnv)

		kafkaMessage := &kf.KafkaMessage{
			Type: &kf.KafkaMessage_Regular{
				Regular: &kf.KafkaMessageRegular{
					Payload:              regMessagePayload,
					ConfigSeq:            env.KafkaPayload.KafkaRegularMessage.ConfigSeq,
					Class:                kf.KafkaMessageRegular_Class(env.KafkaPayload.KafkaRegularMessage.Class),
					OriginalOffset:       env.KafkaPayload.KafkaRegularMessage.OriginalOffset,
					XXX_NoUnkeyedLiteral: env.KafkaPayload.KafkaRegularMessage.XXX_NoUnkeyedLiteral,
					XXX_unrecognized:     env.KafkaPayload.KafkaRegularMessage.XXX_unrecognized,
					XXX_sizecache:        env.KafkaPayload.KafkaRegularMessage.XXX_sizecache,
				},
			},
		}

		marshaledData, _ := proto.Marshal(kafkaMessage)

		//the signed data consists of bytesOf(KafkaOffset) + bytesOf(KafkaTimestamp) + marshaledData

		kafkaSignedData := make([]byte, 16)
		binary.BigEndian.PutUint64(kafkaSignedData[0:8], uint64(env.KafkaPayload.KafkaOffset))
		binary.BigEndian.PutUint64(kafkaSignedData[8:16], uint64(env.KafkaPayload.KafkaTimestamp))
		kafkaSignedData = append(kafkaSignedData, marshaledData...)

		//Verify Merkle Proof
		if !proof.VerifyProof(kafkaSignedData) {
			if !lastBlock {
				return fmt.Errorf("Peer should have not accepted blocks containing an invalid Merkle Proof. Furthermore, the orderer should not have forwarded a transaction with an invalid merkle proof")
			} else {
				return fmt.Errorf("Orderer forwarded a transaction with an invalid merkle proof")
			}
		}

		//Verify Signature
		if proof.VerifySignatureWithPath(env.KafkaPayload.KafkaSignatureHeader, pkPath) != nil {
			if !lastBlock {
				return fmt.Errorf("Peer should have not accepted blocks containing an invalid Kafka signature. Furthermore, the orderer should not have forwarded a transaction with an invalid Kafka signature")
			} else {
				return fmt.Errorf("Orderer forwarded a transaction with an invalid Kafka signature")
			}
		}
	}
	return nil
}

// GetKafkaSeqNrFromEnvelope retrieves the sequence number of the given envelope
func GetKafkaSeqNrFromEnvelope(env *cb.Envelope) int64 {
	if env.KafkaPayload == nil {
		return -1
	}
	return env.KafkaPayload.KafkaOffset
}

// GetKafkaSeqNrFromMetadata retrieves the sequence number of the given ttc message
func GetKafkaSeqNrFromMetadata(kafkaMetadata *kf.KafkaMetadata) int64 {
	if kafkaMetadata.ReceivedTTCMessage {
		return int64(binary.BigEndian.Uint64(kafkaMetadata.KafkaPayload.ConsumerMessageBytes[0:8]))
	}
	return -1
}
