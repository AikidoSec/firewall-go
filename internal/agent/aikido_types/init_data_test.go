package aikido_types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCloudConfigData_UpdatedAt(t *testing.T) {
	config := &CloudConfigData{
		ConfigUpdatedAt: 1701388800000, // 2023-12-01 00:00:00 UTC
	}

	result := config.UpdatedAt()
	expected := time.UnixMilli(1701388800000)

	assert.Equal(t, expected, result)
}
