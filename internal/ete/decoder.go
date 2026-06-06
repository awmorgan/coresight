package ete

import (
	"fmt"

	"github.com/awmorgan/coresight/internal/etmv4"
	"github.com/awmorgan/coresight/trace"
)

type Decoder struct {
	*etmv4.Decoder
}

func NewDecoder(cfg *Config, mem trace.MemoryReader, instr trace.InstructionDecoder) (*Decoder, error) {
	if cfg == nil || cfg.Config == nil {
		return nil, fmt.Errorf("%w: ETE config cannot be nil", trace.ErrInvalidParamVal)
	}
	dec, err := etmv4.NewDecoder(cfg.Config, mem, instr)
	if err != nil {
		return nil, err
	}
	return &Decoder{Decoder: dec}, nil
}
