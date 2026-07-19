package parser

import "testing"

func TestClassify(t *testing.T) {
	cls := DefaultClassifier()
	cases := []struct {
		name string
		min  RiskProfile
	}{
		{"user_id", RiskHigh},
		{"id", RiskHigh},
		{"redirect", RiskHigh},
		{"cmd", RiskCritical},
		{"token", RiskCritical},
		{"theme_color", RiskLow},
		{"lang", RiskLow},
	}
	for _, c := range cases {
		got, reasons := cls.Classify(c.name, "")
		if got < c.min {
			t.Errorf("Classify(%q) = %s, want >= %s (%v)", c.name, got, c.min, reasons)
		}
	}
}

func TestFromQueryClassifies(t *testing.T) {
	e := NewExtractor(nil)
	ps := e.FromQuery("user_id=5&theme_color=red&cmd=ls")
	risk := map[string]RiskProfile{}
	for _, p := range ps {
		risk[p.Name] = p.Risk
	}
	if risk["user_id"] < RiskHigh {
		t.Errorf("user_id should be high, got %s", risk["user_id"])
	}
	if risk["cmd"] < RiskCritical {
		t.Errorf("cmd should be critical, got %s", risk["cmd"])
	}
	if risk["theme_color"] != RiskLow {
		t.Errorf("theme_color should be low, got %s", risk["theme_color"])
	}
}

func TestFromHTMLHiddenInputs(t *testing.T) {
	html := `<form><input type="hidden" name="csrf_token" value="abc"><input name="account_id"></form>`
	e := NewExtractor(nil)
	ps := e.FromHTML([]byte(html))
	names := map[string]bool{}
	for _, p := range ps {
		names[p.Name] = true
	}
	if !names["csrf_token"] || !names["account_id"] {
		t.Fatalf("expected hidden inputs discovered, got %v", names)
	}
}
