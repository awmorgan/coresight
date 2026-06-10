package coresight

import (
	"fmt"

)

type eteDecoder struct {
	*etmv4Decoder
}

func eteNewDecoder(cfg *eteConfig, mem MemoryReader, instr internalInstructionDecoder) (*eteDecoder, error) {
	if cfg == nil || cfg.etmv4Config == nil {
		return nil, fmt.Errorf("%w: ETE config cannot be nil", errInvalidParamVal)
	}
	dec, err := etmv4NewDecoder(cfg.etmv4Config, mem, instr)
	if err != nil {
		return nil, err
	}
	return &eteDecoder{etmv4Decoder: dec}, nil
}
