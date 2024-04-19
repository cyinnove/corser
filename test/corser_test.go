package corser

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/zomasec/corser/pkg/corser"
	"testing"
)

func Test_Suffix(t *testing.T) {

	h, _ := corser.NetParser("sub.target.com")

	scan := &corser.Scanner{
		Origin: "zomasec.io",
		Host: &corser.Host{
			Domain:    h.Domain,
			Subdomain: h.Subdomain,
			TLD:       h.TLD,
		},
	}

	scan.Suffix()

	want := []string{"https://zomasec.io.target.com"}
	got := scan.Payloads

	assert.ElementsMatch(t, want, got, "Want %v but got %v", want, got)
}

func Test_Prefix(t *testing.T) {
	h, _ := corser.NetParser("sub.target.com")

	scan := &corser.Scanner{
		Origin: "zomasec.io",
		Host: &corser.Host{
			Domain:    h.Domain,
			Subdomain: h.Subdomain,
			TLD:       h.TLD,
		},
	}

	scan.Prefix()

	want := []string{"https://target.com.zomasec.io"}
	got := scan.Payloads

	assert.ElementsMatch(t, want, got, "Want %v but got %v", want, got)
}

func Test_Wildcard(t *testing.T) {

	h, _ := corser.NetParser("sub.target.com")

	scan := &corser.Scanner{
		Origin: "zomasec.io",
		Host: &corser.Host{
			Full:      h.Full,
			Domain:    h.Domain,
			Subdomain: h.Subdomain,
			TLD:       h.TLD,
		},
	}

	scan.Wildcard()

	want := []string{"https://zomasec.io/sub.target.com"}
	got := scan.Payloads

	assert.ElementsMatch(t, want, got, "Want %v but got %v", want, got)
}

func Test_NetParser(t *testing.T) {

	t.Run("Case no subdomain", func(t *testing.T) {
		parsed, _ := corser.NetParser("zomasec.io")

		got := parsed.Subdomain

		assert.Emptyf(t, got, "Subdomain is not empty")

	})

	t.Run("Case there is subdomain", func(t *testing.T) {
		parsed, _ := corser.NetParser("sub.zomasec.io")

		want := "sub."

		got := parsed.Subdomain

		assert.Equalf(t, want, got, "Want %v but got %v", want, got)

	})

	t.Run("Case full domain", func(t *testing.T) {
		parsed, _ := corser.NetParser("sub.zomasec.io")

		want := "sub.zomasec.io"
		fmt.Println(parsed.Full)
		got := parsed.Full

		assert.Equalf(t, want, got, "Want %v but got %v", want, got)

	})

}
