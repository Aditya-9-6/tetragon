// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/selectors"
)

// SensorCapabilities defines the supported selectors and actions for a tracing sensor.
type SensorCapabilities struct {
	Name string

	// SupportedActions defines an allowlist of supported actions (lowercase).
	// If non-empty, any action not present in this map is rejected.
	SupportedActions map[string]struct{}

	// DisallowedActions maps action names (lowercase) to specific rejection error messages.
	DisallowedActions map[string]string

	// AllowMatchReturnArgs specifies whether MatchReturnArgs selector is supported.
	AllowMatchReturnArgs bool

	// DisallowStackTrace specifies whether all stacktrace actions (kernel and user) are disallowed.
	DisallowStackTrace bool

	// DisallowKernelStackTrace specifies whether KernelStackTrace is disallowed.
	DisallowKernelStackTrace bool

	// RequirePostForUserStackTrace specifies whether UserStackTrace requires the Post action.
	RequirePostForUserStackTrace bool

	// RequireEnforcersForNotify specifies whether NotifyEnforcer requires at least one enforcer in spec.Enforcers.
	RequireEnforcersForNotify bool
}

// validateSensorSelectors validates selector definitions and actions against a sensor's declared capabilities.
func validateSensorSelectors(
	caps SensorCapabilities,
	sels []v1alpha1.KProbeSelector,
	enforcers []v1alpha1.EnforcerSpec,
) error {
	for sid, s := range sels {
		if !caps.AllowMatchReturnArgs && len(s.MatchReturnArgs) > 0 {
			return errors.New("MatchReturnArgs selector is not supported")
		}

		allActions := slices.Concat(s.MatchActions, s.MatchReturnActions)
		for mid, action := range allActions {
			actName := strings.ToLower(action.Action)

			// Check explicit disallowed action messages
			if msg, ok := caps.DisallowedActions[actName]; ok {
				return errors.New(msg)
			}

			// Check allowlist
			if len(caps.SupportedActions) > 0 {
				if _, ok := caps.SupportedActions[actName]; !ok {
					return fmt.Errorf("%s action is not supported", action.Action)
				}
			}

			// Check stacktrace constraints
			if caps.DisallowStackTrace && (action.KernelStackTrace || action.UserStackTrace) {
				return errors.New("stacktrace actions are not supported")
			}
			if caps.DisallowKernelStackTrace && action.KernelStackTrace {
				return fmt.Errorf("kernelStackTrace is not supported for %s: got kernelStackTrace enabled in selectors[%d].matchActions[%d]", caps.Name, sid, mid)
			}
			if caps.RequirePostForUserStackTrace && action.UserStackTrace && action.Action != "Post" {
				return fmt.Errorf("userStackTrace can only be used along Post action: got userStackTrace enabled in selectors[%d].matchActions[%d] with action '%s'", caps.Name, sid, mid, action.Action)
			}

			// Uprobe Set action constraint
			if caps.Name == "uprobe" && action.Action == "Set" {
				if action.ArgIndex >= selectors.ArgsInRegisters {
					return fmt.Errorf("uprobe Set action argIndex %d out of range", action.ArgIndex)
				}
			}
		}

		// Also check enforcer / geturl helper detectors in case they appear across selector fields
		if caps.DisallowedActions != nil {
			if msg, ok := caps.DisallowedActions["notifyenforcer"]; ok {
				if selectors.HasEnforcerAction([]v1alpha1.KProbeSelector{s}) {
					return errors.New(msg)
				}
			}
			if msg, ok := caps.DisallowedActions["geturl"]; ok {
				if selectors.HasGetUrlOrDnsLookup([]v1alpha1.KProbeSelector{s}) {
					return errors.New(msg)
				}
			}
		}
	}

	if caps.RequireEnforcersForNotify && selectors.HasNotifyEnforcerAction(sels) && len(enforcers) == 0 {
		return errors.New("NotifyEnforcer action specified, but spec contains no enforcers")
	}

	return nil
}
