package transits

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetTransits(t *testing.T) {
	examinePath := func(op string, args []string, deferReporting bool) error {
		return nil
	}
	examineCommand := func(ctx context.Context, op string, args []string) error {
		return nil
	}

	SetTransits(examinePath, examineCommand)

	assert.NotNil(t, ExaminePath())
	assert.NotNil(t, ExamineCommand())
}

func TestExaminePath(t *testing.T) {
	called := false
	examinePath := func(op string, args []string, deferReporting bool) error {
		called = true
		return nil
	}

	SetTransits(examinePath, nil)
	fn := ExaminePath()
	_ = fn("test", []string{}, false)

	assert.True(t, called)
}

func TestExamineCommand(t *testing.T) {
	called := false
	examineCommand := func(ctx context.Context, op string, args []string) error {
		called = true
		return nil
	}

	SetTransits(nil, examineCommand)
	fn := ExamineCommand()
	_ = fn(context.Background(), "test", []string{})

	assert.True(t, called)
}
