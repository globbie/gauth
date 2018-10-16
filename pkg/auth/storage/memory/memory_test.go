package memoryStorage

import (
	"github.com/globbie/gnode/pkg/auth/storage"
	"testing"
)

func TestStorage(t *testing.T) {
	s := New()
	storage.CRUDCheckRun(t, s)
}
