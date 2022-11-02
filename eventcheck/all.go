package eventcheck

import (
	"github.com/Fantom-foundation/go-opera/eventcheck/basiccheck"
	"github.com/Fantom-foundation/go-opera/eventcheck/epochcheck"
	"github.com/Fantom-foundation/go-opera/eventcheck/gaspowercheck"
	"github.com/Fantom-foundation/go-opera/eventcheck/heavycheck"
	"github.com/Fantom-foundation/go-opera/eventcheck/parentscheck"
	"github.com/Fantom-foundation/go-opera/inter"
)

// Checkers is collection of all the checkers
type Checkers struct {
	Basiccheck    *basiccheck.Checker
	Epochcheck    *epochcheck.Checker
	Parentscheck  *parentscheck.Checker
	Gaspowercheck *gaspowercheck.Checker
	Heavycheck    *heavycheck.Checker
}

// Validate runs all the checks except Poset-related
func (v *Checkers) Validate(e inter.EventPayloadI, parents inter.EventIs) error {
	//基础校验
	if err := v.Basiccheck.Validate(e); err != nil {
		return err
	}
	//有效性校验
	if err := v.Epochcheck.Validate(e); err != nil {
		return err
	}
	//上级检查
	if err := v.Parentscheck.Validate(e, parents); err != nil {
		return err
	}
	//本级的内部检查
	var selfParent inter.EventI
	if e.SelfParent() != nil {
		selfParent = parents[0]
	}
	//gas的检查
	if err := v.Gaspowercheck.Validate(e, selfParent); err != nil {
		return err
	}
	//深度检查
	if err := v.Heavycheck.ValidateEvent(e); err != nil {
		return err
	}
	return nil
}
