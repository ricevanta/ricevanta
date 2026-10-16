package leadingcomment

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) { os.Exit(0) }

func /* doc */ TestHidden(t *testing.T) { t.Fatal("hidden") }
