package test

import (
	"corser/pkg/requester"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestRequest_SetClient(t *testing.T) {
	req := requester.NewRequester("GET", "", "", 10)

	got := req.SetClient().Timeout
	want := time.Duration(10 * time.Second)

	assert.Equalf(t, want, got, "Want %s, but got %s", want, got)

}

func TestRequest_addCustomHeader(t *testing.T) {

}
