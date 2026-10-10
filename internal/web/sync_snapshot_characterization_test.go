package web

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCurrentSyncJobAfterOwnsFilteredEvents(t *testing.T) {
	for name, tc := range map[string]struct {
		sequence int
		want     []syncJobEvent
	}{
		"full snapshot":          {0, []syncJobEvent{{Sequence: 2}, {Sequence: 9}, {Sequence: 5}}},
		"cursor is not an index": {5, []syncJobEvent{{Sequence: 9}}},
		"retains event order":    {1, []syncJobEvent{{Sequence: 2}, {Sequence: 9}, {Sequence: 5}}},
		"no later events":        {9, []syncJobEvent{}},
	} {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			live := &syncJobSnapshot{ID: "troy-sync", Message: "running", LatestSequence: 9, Events: []syncJobEvent{{Sequence: 2}, {Sequence: 9}, {Sequence: 5}}}
			a := &webApp{syncJobs: map[string]*syncJobSnapshot{"greendale": live}}
			got := a.currentSyncJobAfter("greendale", tc.sequence)
			r.Equal(tc.want, got.Events)
			r.Equal(live.ID, got.ID)
			r.Equal(live.LatestSequence, got.LatestSequence)
			got.Message = "changed"
			if len(got.Events) > 0 {
				got.Events[0].Detail = "changed"
			}
			got.Events = append(got.Events, syncJobEvent{Sequence: 20})
			r.Equal("running", live.Message)
			r.Equal([]syncJobEvent{{Sequence: 2}, {Sequence: 9}, {Sequence: 5}}, live.Events)
			r.Nil(a.currentSyncJobAfter("missing", tc.sequence))
		})
	}
}

func BenchmarkCurrentSyncJobAfter(b *testing.B) {
	events := make([]syncJobEvent, 10000)
	for i := range events {
		events[i].Sequence = i + 1
	}
	a := &webApp{syncJobs: map[string]*syncJobSnapshot{"greendale": {Events: events}}}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		a.currentSyncJobAfter("greendale", 9999)
	}
}
