package mghclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mpaishon/mghclient/internal/protocol"
	"github.com/mpaishon/mghclient/internal/relayclient/relaytest"
)

// oldReport is InstanceReport as a relay that predates install modes
// decodes it.
type oldReport struct {
	Version     string `json:"version"`
	Platform    string `json:"platform"`
	UpdateState string `json:"update_state,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

// fakeReports wraps the fake relay so POST /relay/apps/<app>/report is
// answered as an old relay would (encoding/json, unknown fields ignored, as
// gin's ShouldBindJSON), keeping every raw body.
func fakeReports(t *testing.T) (*relaytest.Server, func() []string) {
	t.Helper()
	s := relaytest.New(t, relaytest.Data{Profile: relaytest.OwnerProfile()})
	var mu sync.Mutex
	var bodies []string
	next := s.Relay.Config.Handler
	s.Relay.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/report") {
			next.ServeHTTP(w, r)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(raw))
		mu.Unlock()
		var rep oldReport
		if err := json.Unmarshal(raw, &rep); err != nil || rep.Platform == "" {
			http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protocol.InstanceReply{Every: 300, Offer: &protocol.Offer{App: "localdraw", Version: "v2", Policy: protocol.UpdateNotify, AssetID: 1}})
	})
	return s, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), bodies...)
	}
}

func enrolled(t *testing.T, s *relaytest.Server, cfg Config) *Instance {
	t.Helper()
	inst, err := Enrol(context.Background(), cfg, EnrolOptions{URL: s.WebURL, Code: relaytest.Code, AcceptFingerprint: s.WebFingerprint, Hostname: "nas02"})
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	return inst
}

// TestInstallModeOnTheWire: Config.InstallMode rides on every Report (Run's
// too); a self-updating install sends exactly the bytes an older SDK did;
// a relay that predates the field still takes the report and answers it.
func TestInstallModeOnTheWire(t *testing.T) {
	s, bodies := fakeReports(t)
	dir := filepath.Join(t.TempDir(), "relay")
	cfg := Config{App: "localdraw", StateDir: dir, Version: "v1", Platform: "linux-amd64", InstallMode: InstallReport}
	inst := enrolled(t, s, cfg)
	ctx := context.Background()

	reply, err := inst.Report(ctx, Report{})
	if err != nil || reply.Offer == nil || reply.Offer.Version != "v2" {
		t.Fatalf("report to an old relay = %+v %v", reply, err)
	}
	var sent protocol.InstanceReport
	if b := bodies(); len(b) != 1 || json.Unmarshal([]byte(b[0]), &sent) != nil || sent.InstallMode != InstallReport || sent.Version != "v1" {
		t.Fatalf("sent %q", b)
	}

	// Run's reports carry it as well.
	runCtx, cancel := context.WithCancel(ctx)
	if err := inst.Run(runCtx, RunOptions{OnOffer: func(*Offer) { cancel() }}); err != nil {
		t.Fatalf("run = %v", err)
	}
	if b := bodies(); len(b) != 2 || !strings.Contains(b[1], `"install_mode":"report"`) {
		t.Fatalf("Run sent %q", b)
	}

	// Self-updating (the default): no install_mode on the wire at all.
	self, err := Open(Config{App: "localdraw", StateDir: dir, Version: "v1", Platform: "linux-amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := self.Report(ctx, Report{UpdateState: StateConfirmed}); err != nil {
		t.Fatal(err)
	}
	if b := bodies(); strings.Contains(b[2], "install_mode") {
		t.Fatalf("a self-updating report sent %q", b[2])
	}

	// A reports-only install never downloads.
	if err := inst.Download(ctx, reply.Offer, io.Discard, nil); !errors.Is(err, ErrReportsOnly) {
		t.Fatalf("download = %v, want ErrReportsOnly", err)
	}
	if err := inst.DownloadFile(ctx, reply.Offer, filepath.Join(t.TempDir(), "x.zip"), nil); !errors.Is(err, ErrReportsOnly) {
		t.Fatalf("download file = %v, want ErrReportsOnly", err)
	}
	if _, err := inst.Report(ctx, Report{InstallMode: "container"}); err == nil {
		t.Fatal("an unknown install mode was sent")
	}
	if len(bodies()) != 3 {
		t.Fatal("a refused report reached the relay")
	}
}

func TestConfigRefusesAnUnknownInstallMode(t *testing.T) {
	if _, err := Open(Config{App: "x", StateDir: t.TempDir(), InstallMode: "docker"}); err == nil || errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("Open with an unknown install mode = %v", err)
	}
	for _, m := range []string{"", InstallSelf, InstallReport} {
		if _, err := Open(Config{App: "x", StateDir: t.TempDir(), InstallMode: m}); !errors.Is(err, ErrNotEnrolled) {
			t.Fatalf("Open with mode %q = %v, want ErrNotEnrolled", m, err)
		}
	}
}
