package verdicts

import "fmt"

type VerdictType int16

const KAFKA_VERDICT = 0
const ORDERER_VERDICT = 1
const PEER_VERDICT = 2

type Verdict struct {
	verdict  string
	identity string

	verdictType VerdictType
}

func CreateVerdict(verdict string, identity string, verdictType VerdictType) *Verdict {
	if verdict == "" || verdictType < 0 || verdictType > 2 {
		return nil
	}
	if identity == "" && verdictType != 0 {
		return nil
	}
	return &Verdict{
		verdict:     verdict,
		identity:    identity,
		verdictType: verdictType,
	}
}

func (v *Verdict) EvaluateVerdict() string {
	if v.verdictType == 0 {
		return fmt.Sprintf("VERDICT (KafkaCluster): %s", v.verdict)
	} else if v.verdictType == 1 {
		return fmt.Sprintf("VERDICT (Orderer of %s): %s", v.identity, v.verdict)
	} else if v.verdictType == 2 {
		return fmt.Sprintf("VERDICT (%s): %s", v.identity, v.verdict)
	}
	return ""
}
