package relayclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/mpaishon/mghclient/internal/protocol"
)

// The upgrade gateway's routes for an app instance
// (docs/UPGRADE_GATEWAY.md §6.2, §13): the offer, the app's releases, its
// assets and the report. Every one is scoped by the relay to this client's
// own app; another app's is 403.

// AppUpdate is GET /relay/apps/<app>/update: the offer for platform
// (goos-arch), nil when there is none. current is the version running, so
// the relay answers nothing when it is up to date.
func (c *Client) AppUpdate(ctx context.Context, app, platform, current string) (*protocol.Offer, error) {
	q := url.Values{}
	q.Set("platform", platform)
	if current != "" {
		q.Set("current", current)
	}
	var o protocol.Offer
	code, err := c.getJSON(ctx, protocol.AppPath(url.PathEscape(app), "/update"), q, &o)
	if err != nil {
		return nil, err
	}
	if code == http.StatusNoContent || o.Version == "" {
		return nil, nil
	}
	return &o, nil
}

// AppReleases is GET /relay/apps/<app>/releases: the releases this instance
// may see (its channel, promoted).
func (c *Client) AppReleases(ctx context.Context, app string) ([]protocol.Release, error) {
	var out struct {
		Releases []protocol.Release `json:"releases"`
	}
	_, err := c.getJSON(ctx, protocol.AppPath(url.PathEscape(app), "/releases"), nil, &out)
	return out.Releases, err
}

// AppDownload streams one of the app's assets to dst, hashing as it
// writes; expectSHA (the offer's) must equal X-Content-SHA256, and the
// bytes must hash to it, or the download is refused and dst must not be
// used.
func (c *Client) AppDownload(ctx context.Context, app string, assetID int64, expectSHA string, dst io.Writer, progress func(int64)) (DownloadInfo, error) {
	resp, err := c.do(ctx, http.MethodGet, protocol.AppPath(url.PathEscape(app), "/assets/"+strconv.FormatInt(assetID, 10)), nil, nil)
	if err != nil {
		return DownloadInfo{}, err
	}
	defer resp.Body.Close()
	info := DownloadInfo{Cache: resp.Header.Get(protocol.HeaderCache)}
	return info, verifiedCopy(resp, expectSHA, dst, progress, &info)
}

// AppReport is POST /relay/apps/<app>/report: what this instance runs. The
// reply says when to check again and carries the offer, so a client that
// reports needs no separate check.
func (c *Client) AppReport(ctx context.Context, app string, rep protocol.InstanceReport) (protocol.InstanceReply, error) {
	var out protocol.InstanceReply
	body, err := json.Marshal(rep)
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	path := protocol.AppPath(url.PathEscape(app), "/report")
	resp, err := c.do(ctx, http.MethodPost, path, nil, bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if err := decode(resp.Body, &out); err != nil {
		return out, fmt.Errorf("relay %s%s: %w", c.host(), path, err)
	}
	c.learn(out.Relay)
	return out, nil
}

// IsRefused reports whether err is the relay refusing this client's
// certificate — revoked, deleted or never enrolled — rather than a network
// failure or a refusal of one request: a TLS alert about the certificate,
// a 401, or the 403 the relay gives a certificate it no longer honours.
func IsRefused(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrRefused) || errors.Is(err, ErrRevoked) || certificateRefused(err) {
		return true
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code == http.StatusUnauthorized ||
			(se.Code == http.StatusForbidden && se.WAN == "" && strings.Contains(strings.ToLower(se.Message), "revoked"))
	}
	return false
}
