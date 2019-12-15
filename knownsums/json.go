package knownsums

import (
	"encoding/hex"
	"encoding/json"
)

type jsonKnownSum struct {
	Name     string `json:"name"`
	HashName string `json:"hash"`
	Checksum string `json:"checksum"`
}

func (j *jsonKnownSum) knownSum() (*knownSum, error) {
	sum, err := hex.DecodeString(j.Checksum)
	if err != nil {
		return nil, err
	}
	return &knownSum{
		Name:     j.Name,
		HashName: j.HashName,
		Checksum: sum,
	}, nil
}

func (k *knownSum) jsonKnownSum() *jsonKnownSum {
	return &jsonKnownSum{
		Name:     k.Name,
		HashName: k.HashName,
		Checksum: hex.EncodeToString(k.Checksum),
	}
}

func (k *knownSum) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.jsonKnownSum())
}

func (k *knownSum) UnmarshalJSON(data []byte) error {
	j := &jsonKnownSum{}
	err := json.Unmarshal(data, j)
	if err != nil {
		return err
	}
	k2, err := j.knownSum()
	if err != nil {
		return err
	}
	*k = *k2
	return nil
}

func (k *KnownSums) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.knownSums)
}

func (k *KnownSums) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &k.knownSums)
}
