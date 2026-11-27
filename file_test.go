package proton_api_bridge

import (
	"testing"
	"time"

	proton "github.com/rclone/go-proton-api"
)

func TestRevisionModificationTime(t *testing.T) {
	link := &proton.Link{ModifyTime: 1700000000}

	got, err := revisionModificationTime(link, &proton.RevisionXAttrCommon{ModificationTime: "2026-04-15T14:32:08.000Z"})
	if err != nil {
		t.Fatalf("recorded time: %v", err)
	}
	if want := time.Date(2026, 4, 15, 14, 32, 8, 0, time.UTC); !got.Equal(want) {
		t.Errorf("recorded time: got %v, want %v", got, want)
	}

	got, err = revisionModificationTime(link, &proton.RevisionXAttrCommon{})
	if err != nil {
		t.Fatalf("no recorded time: %v", err)
	}
	if want := time.Unix(link.ModifyTime, 0); !got.Equal(want) {
		t.Errorf("no recorded time: got %v, want %v", got, want)
	}

	if _, err = revisionModificationTime(link, &proton.RevisionXAttrCommon{ModificationTime: "not a time"}); err == nil {
		t.Error("malformed time: got no error")
	}
}
