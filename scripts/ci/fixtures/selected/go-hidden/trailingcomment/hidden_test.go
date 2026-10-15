package trailingcomment

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) { os.Exit(0) }

func TestHidden /* doc */ (t *testing.T) { t.Fatal("hidden") }
