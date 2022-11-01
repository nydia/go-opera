//这个文件我立即是作为一个适配器，检查

package heavycheck

import (
	"github.com/Fantom-foundation/lachesis-base/inter/dag"

	"github.com/Fantom-foundation/go-opera/inter"
)

// 仅事件检查结构体
type EventsOnly struct {
	*Checker
}

// 入队检查
func (c *EventsOnly) Enqueue(e dag.Event, onValidated func(error)) error {
	return c.Checker.EnqueueEvent(e.(inter.EventPayloadI), onValidated)
}

// 仅事件检查结构体
type BVsOnly struct {
	*Checker
}

func (c *BVsOnly) Enqueue(bvs inter.LlrSignedBlockVotes, onValidated func(error)) error {
	return c.Checker.EnqueueBVs(bvs, onValidated)
}

type EVOnly struct {
	*Checker
}

func (c *EVOnly) Enqueue(ers inter.LlrSignedEpochVote, onValidated func(error)) error {
	return c.Checker.EnqueueEV(ers, onValidated)
}
