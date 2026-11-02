// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func TestValidateSensorSelectorsLSM(t *testing.T) {
	// 1. Valid actions should pass
	validSels := []v1alpha1.KProbeSelector{
		{
			MatchActions: []v1alpha1.ActionSelector{
				{Action: "Sigkill"},
				{Action: "Signal"},
				{Action: "NoPost"},
				{Action: "Override"},
				{Action: "UpdateState"},
				{Action: "Post"},
			},
		},
	}
	require.NoError(t, validateSensorSelectors(lsmCapabilities, validSels, nil))

	// 2. Unsupported action should fail
	unsupportedActionSels := []v1alpha1.KProbeSelector{
		{
			MatchActions: []v1alpha1.ActionSelector{
				{Action: "NotifyEnforcer"},
			},
		},
	}
	err := validateSensorSelectors(lsmCapabilities, unsupportedActionSels, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "NotifyEnforcer action is not supported")

	// 3. MatchReturnArgs should fail for LSM
	matchReturnSels := []v1alpha1.KProbeSelector{
		{
			MatchReturnArgs: []v1alpha1.ArgSelector{
				{Index: 0, Operator: "Equal"},
			},
		},
	}
	err = validateSensorSelectors(lsmCapabilities, matchReturnSels, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "MatchReturnArgs selector is not supported")

	// 4. Stacktrace actions should fail for LSM
	stackTraceSels := []v1alpha1.KProbeSelector{
		{
			MatchActions: []v1alpha1.ActionSelector{
				{Action: "Post", KernelStackTrace: true},
			},
		},
	}
	err = validateSensorSelectors(lsmCapabilities, stackTraceSels, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "stacktrace actions are not supported")
}

func TestValidateSensorSelectorsKprobeAndTracepoint(t *testing.T) {
	notifySels := []v1alpha1.KProbeSelector{
		{
			MatchActions: []v1alpha1.ActionSelector{
				{Action: "NotifyEnforcer"},
			},
		},
	}

	// Without enforcers: must fail
	err := validateSensorSelectors(kprobeCapabilities, notifySels, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "NotifyEnforcer action specified, but spec contains no enforcers")

	err = validateSensorSelectors(tracepointCapabilities, notifySels, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "NotifyEnforcer action specified, but spec contains no enforcers")

	// With enforcers: must pass
	enforcers := []v1alpha1.EnforcerSpec{{}}
	require.NoError(t, validateSensorSelectors(kprobeCapabilities, notifySels, enforcers))
	require.NoError(t, validateSensorSelectors(tracepointCapabilities, notifySels, enforcers))
}

func TestValidateSensorSelectorsUprobe(t *testing.T) {
	// 1. Enforcer actions unsupported
	enforcerSels := []v1alpha1.KProbeSelector{
		{
			MatchActions: []v1alpha1.ActionSelector{
				{Action: "NotifyEnforcer"},
			},
		},
	}
	err := validateSensorSelectors(uprobeCapabilities, enforcerSels, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "enforcer actions are not supported for uprobes")

	// 2. GetUrl / DnsLookup unsupported
	getUrlSels := []v1alpha1.KProbeSelector{
		{
			MatchActions: []v1alpha1.ActionSelector{
				{Action: "GetUrl"},
			},
		},
	}
	err = validateSensorSelectors(uprobeCapabilities, getUrlSels, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "GetUrl and DnsLookup actions not supported")

	// 3. Kernel stacktrace unsupported
	kernelStackSels := []v1alpha1.KProbeSelector{
		{
			MatchActions: []v1alpha1.ActionSelector{
				{Action: "Post", KernelStackTrace: true},
			},
		},
	}
	err = validateSensorSelectors(uprobeCapabilities, kernelStackSels, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "kernelStackTrace is not supported for uprobes")

	// 4. User stacktrace requires Post
	userStackNoPostSels := []v1alpha1.KProbeSelector{
		{
			MatchActions: []v1alpha1.ActionSelector{
				{Action: "NoPost", UserStackTrace: true},
			},
		},
	}
	err = validateSensorSelectors(uprobeCapabilities, userStackNoPostSels, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "userStackTrace can only be used along Post action")

	userStackPostSels := []v1alpha1.KProbeSelector{
		{
			MatchActions: []v1alpha1.ActionSelector{
				{Action: "Post", UserStackTrace: true},
			},
		},
	}
	require.NoError(t, validateSensorSelectors(uprobeCapabilities, userStackPostSels, nil))

	// 5. Set action argIndex range
	setOutOfRangeSels := []v1alpha1.KProbeSelector{
		{
			MatchActions: []v1alpha1.ActionSelector{
				{Action: "Set", ArgIndex: 100},
			},
		},
	}
	err = validateSensorSelectors(uprobeCapabilities, setOutOfRangeSels, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "uprobe Set action argIndex 100 out of range")
}

func TestValidateSensorSelectorsUSDT(t *testing.T) {
	// 1. Enforcer actions unsupported
	enforcerSels := []v1alpha1.KProbeSelector{
		{
			MatchActions: []v1alpha1.ActionSelector{
				{Action: "NotifyEnforcer"},
			},
		},
	}
	err := validateSensorSelectors(usdtCapabilities, enforcerSels, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "enforcer actions are not supported")

	// 2. GetUrl / DnsLookup unsupported
	getUrlSels := []v1alpha1.KProbeSelector{
		{
			MatchActions: []v1alpha1.ActionSelector{
				{Action: "DnsLookup"},
			},
		},
	}
	err = validateSensorSelectors(usdtCapabilities, getUrlSels, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "GetUrl and DnsLookup actions not supported")

	// 3. Valid actions pass
	validSels := []v1alpha1.KProbeSelector{
		{
			MatchActions: []v1alpha1.ActionSelector{
				{Action: "Post"},
				{Action: "Sigkill"},
			},
		},
	}
	require.NoError(t, validateSensorSelectors(usdtCapabilities, validSels, nil))
}
