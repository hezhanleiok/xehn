//go:build windows

package main

import "testing"

// TestAboutLayoutFitsBody pins the About page's vertical budget. The page does
// not scroll, so every card, the link card and both footer lines must end above
// the body's bottom edge: a clipped footer would hide the licence sentence the
// page exists to carry, and a card that overruns would paint over the next one.
func TestAboutLayoutFitsBody(t *testing.T) {
	c1, c2, c3, c4, links, footer := aboutLayout(shellBodyY)

	if c1 != shellBodyY {
		t.Fatalf("first card starts at %v, want the body top %v", c1, shellBodyY)
	}
	for i, got := range []float64{c2, c3, c4} {
		want := c1 + float64(i+1)*(aboutCardH+aboutGap)
		if got != want {
			t.Fatalf("card %d starts at %v, want %v", i+2, got, want)
		}
	}
	if want := c4 + aboutCardH + aboutGap; links != want {
		t.Fatalf("link card starts at %v, want %v", links, want)
	}
	if want := links + aboutLinkH + aboutFootG; footer != want {
		t.Fatalf("footer starts at %v, want %v", footer, want)
	}

	bodyBottom := shellBodyY + shellBodyH
	// Footer: a rule 7px above the text, then two lines 18px each with the
	// second starting 20px lower.
	if bottom := footer + 20 + 18; bottom > bodyBottom {
		t.Fatalf("footer ends at %v, past the body bottom %v", bottom, bodyBottom)
	}
	if top := footer - 7; top < links+aboutLinkH {
		t.Fatalf("footer rule at %v overlaps the link card ending at %v", top, links+aboutLinkH)
	}

	// Link card: title band, then five rows. The last row stays inside.
	linkLast := links + 34 + 4*aboutLinkStep + 18
	if linkLast > links+aboutLinkH {
		t.Fatalf("last link row ends at %v, card ends at %v", linkLast, links+aboutLinkH)
	}

	// Card internals: the action row shares the title line, and the two field
	// rows must start below it without leaving the card.
	btnBottom := c1 + aboutBtnTop + aboutBtnH
	fieldTop := c1 + 34
	if btnBottom > fieldTop {
		t.Fatalf("actions end at %v, fields start at %v", btnBottom, fieldTop)
	}
	fieldBottom := fieldTop + aboutKVStep + 20
	if fieldBottom > c1+aboutCardH {
		t.Fatalf("last field row ends at %v, card ends at %v", fieldBottom, c1+aboutCardH)
	}
}

// TestAboutWidthsFit checks the single-column card at the default grid and a wide
// window: the title, the action pair and the two field columns all have to fit
// inside the card's padded width.
func TestAboutWidthsFit(t *testing.T) {
	for _, w := range []float64{858, 1200, 1600} {
		// Actions: two chips at the minimum width plus the gap and right padding.
		actsW := 80*2 + aboutBtnGap + aboutBtnPadR
		if title := 200.0; title+actsW > w-32 {
			t.Fatalf("width %v: title %v and actions %v collide", w, title, actsW)
		}
		// Fields: two label/value pairs with the gap between them.
		colW := (w - 32 - aboutFieldGap) / 2
		if colW < aboutFieldCol+120 {
			t.Fatalf("width %v: field column %v leaves %v for a value", w, colW, colW-aboutFieldCol)
		}
		// Link rows: label column plus a readable address column.
		if got := w - 140; got < 300 {
			t.Fatalf("width %v: link address column is only %v", w, got)
		}
	}
}

// TestAboutLinksAreGitHub pins the rule this page was rewritten for: no local
// path, every row a GitHub address.
func TestAboutLinksAreGitHub(t *testing.T) {
	links := aboutLinks()
	if len(links) == 0 {
		t.Fatal("no links")
	}
	for _, ln := range links {
		if ln.id == "" || ln.label == "" {
			t.Fatalf("incomplete link: %+v", ln)
		}
		if got := shortURL(ln.url); len(got) < len("github.com/") || got[:len("github.com/")] != "github.com/" {
			t.Fatalf("%s: %q is not a github.com address", ln.id, ln.url)
		}
	}
}
