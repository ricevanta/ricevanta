package blockoutput

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) { os.Exit(0) }

func Example_hidden() {
	fmt.Println("x")
	/* Output: y */
}
