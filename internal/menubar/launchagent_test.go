package menubar

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestRenderPlist_RequiredFields(t *testing.T) {
	if _, err := RenderPlist(PlistConfig{Executable: "/x"}); err == nil {
		t.Fatal("expected error for missing Label")
	}
	if _, err := RenderPlist(PlistConfig{Label: "l"}); err == nil {
		t.Fatal("expected error for missing Executable")
	}
}

func TestRenderPlist_ValidXMLAndContents(t *testing.T) {
	data, err := RenderPlist(PlistConfig{
		Label:      LaunchAgentLabel,
		Executable: "/usr/local/bin/totp",
		Args:       []string{"menubar"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Must parse as XML.
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	for {
		_, err := dec.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatalf("invalid XML: %v", err)
		}
	}
	s := string(data)
	for _, want := range []string{
		`<key>Label</key>`,
		`<string>com.agungcandra.totp-cli.menubar</string>`,
		`<key>ProgramArguments</key>`,
		`<string>/usr/local/bin/totp</string>`,
		`<string>menubar</string>`,
		`<key>RunAtLoad</key>`,
		`<true/>`,
		`<key>KeepAlive</key>`,
		`<false/>`,
		`<key>ProcessType</key>`,
		`<string>Interactive</string>`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("plist missing %q\n---\n%s", want, s)
		}
	}
}

func TestRenderPlist_EscapesPath(t *testing.T) {
	// Path with XML-special characters must be escaped, not interpolated raw.
	badPath := `/Users/a&b/<weird>/"path"/totp`
	data, err := RenderPlist(PlistConfig{
		Label:      "x",
		Executable: badPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if strings.Contains(s, badPath) {
		t.Errorf("raw unescaped path leaked into plist:\n%s", s)
	}
	if !strings.Contains(s, `&amp;`) || !strings.Contains(s, `&lt;weird&gt;`) {
		t.Errorf("expected XML escaping, got:\n%s", s)
	}
	// Must still parse as XML.
	if err := xml.Unmarshal(data, new(struct {
		XMLName xml.Name `xml:"plist"`
	})); err != nil {
		t.Fatalf("plist no longer parses after escaping: %v", err)
	}
}

func TestPlistPath(t *testing.T) {
	got := PlistPath("/Users/alice")
	want := "/Users/alice/Library/LaunchAgents/com.agungcandra.totp-cli.menubar.plist"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
