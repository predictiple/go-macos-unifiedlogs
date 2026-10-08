package filtering

import (
	"www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/types"
)

func NewScope() types.Scope {
	scope := vfilter.NewScope()
	for _, p := range GetProtocols() {
		scope.AddProtocolImpl(p)
	}

	return scope
}
