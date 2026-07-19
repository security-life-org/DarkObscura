package dom

import "testing"

func TestAnalyze_PossibleDomXSS(t *testing.T) {
	body := []byte(`<html><script>
	  var x = location.hash.substring(1);
	  document.getElementById('o').innerHTML = x;
	</script><div onclick="doThing()"></div></html>`)
	fs := Analyze(body)
	var xss, sink, evt bool
	for _, f := range fs {
		if f.Class == "dom-xss" && f.Confidence == Possible { xss = true }
		if f.Class == "dom-sink" && f.Sink == "innerHTML" { sink = true }
		if f.Class == "inline-event-handler" { evt = true }
	}
	if !xss { t.Error("expected possible dom-xss (location.hash → innerHTML)") }
	if !sink { t.Error("expected innerHTML sink inventory") }
	if !evt { t.Error("expected inline event handler detection") }
	// zero-FP: nothing must ever be reported as confirmed by static analysis
	for _, f := range fs {
		if f.Confidence != Possible && f.Confidence != Likely {
			t.Errorf("static DOM analysis must never confirm; got %q", f.Confidence)
		}
	}
}

func TestAnalyze_Clean(t *testing.T) {
	if fs := Analyze([]byte(`<html><body><p>hello</p></body></html>`)); len(fs) != 0 {
		t.Errorf("clean page must yield nothing; got %v", fs)
	}
}
