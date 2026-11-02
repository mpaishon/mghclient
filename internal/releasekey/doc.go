// Package releasekey holds the Ed25519 release keys mghagent trusts (compiled in) and the signed-message kind lines. Ported from File Cellar's internal/releasekey.
//
// Owned by A1 (signing in bld) and A6 (verifying) (docs/BUILD_PLAN.md step 1/6). Step 0 created only this
// file; the stream adds the rest. Cross-stream calls go through internal/ports.
package releasekey
