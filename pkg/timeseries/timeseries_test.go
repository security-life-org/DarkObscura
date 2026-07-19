package timeseries

import "testing"

func TestFit(t *testing.T) {
	b := Fit([]float64{10, 12, 11, 13, 9, 10, 11})
	if b.N != 7 {
		t.Fatalf("N = %d, want 7", b.N)
	}
	if b.Mean < 10 || b.Mean > 12 {
		t.Errorf("Mean = %.2f, want ~11", b.Mean)
	}
	if b.StdDev <= 0 {
		t.Errorf("StdDev = %.2f, want > 0", b.StdDev)
	}
}

func TestTestDelay_Confirms(t *testing.T) {
	// Baseline ~20ms, tight variance. A 520ms response after injecting a 500ms
	// delay must confirm.
	b := Fit([]float64{18, 20, 22, 19, 21, 20, 20})
	v := b.TestDelay(520, 500, 3.5)
	if !v.Confirmed {
		t.Fatalf("expected confirmation, got: %s (z=%.1f)", v.Reason, v.ZScore)
	}
}

func TestTestDelay_RejectsJitter(t *testing.T) {
	// A modestly slow response with no injected delay taking effect must NOT
	// confirm — this is the zero-false-positive guard against network noise.
	b := Fit([]float64{18, 20, 22, 19, 21, 20, 20})
	v := b.TestDelay(60, 500, 3.5) // 60ms nowhere near the 500ms injected delay
	if v.Confirmed {
		t.Fatalf("must not confirm on jitter; reason=%s z=%.1f", v.Reason, v.ZScore)
	}
}

func TestTestDelay_RejectsNoDelay(t *testing.T) {
	b := Fit([]float64{100, 100, 100, 100})
	v := b.TestDelay(101, 500, 3.5)
	if v.Confirmed {
		t.Fatalf("must not confirm when delay did not take effect")
	}
}
