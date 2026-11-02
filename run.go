package mghclient

import (
	"context"
	"errors"
	"time"
)

// RunOptions is what Run does with what it learns.
type RunOptions struct {
	// State is the update state to report each cycle ("" for none): where
	// the application's last update stands (StateStaged, StateConfirmed…).
	State func() string
	// Detail, when set, is a short line for the console about that state.
	Detail func() string
	// OnOffer is called with each offer (the same one again on later
	// cycles until it is installed or withdrawn). Honour offer.Policy:
	// PolicyAutomatic installs, PolicyNotify asks the user first.
	OnOffer func(*Offer)
	// OnError is told of a cycle that failed; Run goes on. Nil ignores.
	OnError func(error)
	// Now, when written to, makes Run check at once ("Check now").
	Now <-chan struct{}
}

// renewCheckEvery is how often Run looks at the certificate's renewal.
const renewCheckEvery = 12 * time.Hour

// Run reports and checks on the relay's schedule until ctx ends (nil) or
// the relay refuses the instance (ErrRevoked): report, act on the offer the
// reply carries, wait the reply's Every, again. It renews the certificate
// when due.
func (i *Instance) Run(ctx context.Context, o RunOptions) error {
	var lastRenew time.Time
	for {
		if time.Since(lastRenew) >= renewCheckEvery {
			if _, err := i.RenewIfDue(ctx); err != nil {
				if errors.Is(err, ErrRevoked) {
					return err
				}
				if o.OnError != nil {
					o.OnError(err)
				}
			} else {
				lastRenew = time.Now()
			}
		}
		rep := Report{}
		if o.State != nil {
			rep.UpdateState = o.State()
		}
		if o.Detail != nil {
			rep.Detail = o.Detail()
		}
		reply, err := i.Report(ctx, rep)
		switch {
		case errors.Is(err, ErrRevoked):
			return err
		case err != nil:
			if ctx.Err() != nil {
				return nil
			}
			if o.OnError != nil {
				o.OnError(err)
			}
		case reply.Offer != nil && o.OnOffer != nil:
			o.OnOffer(reply.Offer)
		}
		wait := i.Every()
		if err != nil {
			wait = min(wait, time.Minute) // a failed cycle tries again sooner
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-o.Now:
			t.Stop()
		case <-t.C:
		}
	}
}
