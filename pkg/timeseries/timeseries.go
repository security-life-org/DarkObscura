// Package timeseries provides statistical response-time analysis for detecting
// time-based blind injection (SQLi/NoSQLi). Instead of naively trusting a single
// slow response, it models the baseline latency distribution and asks whether an
// injected delay is a statistically significant outlier — robust to network jitter.
package timeseries

import "math"

// Sample is a measured baseline latency in milliseconds.
type Sample = float64

// Baseline holds summary statistics of normal response latencies.
type Baseline struct {
	Mean   float64
	StdDev float64
	N      int
	Max    float64
}

// Fit computes baseline statistics from a set of latency samples (ms).
func Fit(samples []Sample) Baseline {
	b := Baseline{N: len(samples)}
	if len(samples) == 0 {
		return b
	}
	var sum float64
	for _, s := range samples {
		sum += s
		if s > b.Max {
			b.Max = s
		}
	}
	b.Mean = sum / float64(len(samples))
	var varSum float64
	for _, s := range samples {
		d := s - b.Mean
		varSum += d * d
	}
	b.StdDev = math.Sqrt(varSum / float64(len(samples)))
	return b
}

// Verdict is the result of testing an observed latency against the baseline.
type Verdict struct {
	Observed    float64
	ExpectedMax float64
	ZScore      float64
	Confirmed   bool
	Reason      string
}

// TestDelay evaluates whether an observed latency (ms), taken after injecting a
// payload intended to sleep `injectedDelayMS`, confirms a time-based injection.
//
// A confirmation requires BOTH:
//   - the observed latency exceeds the injected delay plus the baseline mean
//     (the delay actually took effect), and
//   - the observed latency is a strong statistical outlier vs. the baseline
//     (z-score >= zThreshold), so ordinary jitter cannot explain it.
func (b Baseline) TestDelay(observed, injectedDelayMS, zThreshold float64) Verdict {
	std := b.StdDev
	if std < 1 {
		std = 1 // guard against zero-variance baselines
	}
	z := (observed - b.Mean) / std
	v := Verdict{
		Observed:    observed,
		ExpectedMax: b.Mean + injectedDelayMS,
		ZScore:      z,
	}
	delayTookEffect := observed >= b.Mean+injectedDelayMS*0.8
	strongOutlier := z >= zThreshold
	switch {
	case delayTookEffect && strongOutlier:
		v.Confirmed = true
		v.Reason = "observed latency matches injected delay and is a strong statistical outlier"
	case delayTookEffect:
		v.Reason = "delay took effect but not a strong outlier — possible network noise"
	default:
		v.Reason = "no measurable delay attributable to the payload"
	}
	return v
}
