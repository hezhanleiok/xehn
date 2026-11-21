//go:build windows

package main

import (
	"math"
	"strconv"

	"github.com/lxn/walk"
)

// ---------------------------------------------------------------------------
// Primitives
//
// Everything takes design coordinates (the 1080x700 grid) and scales through
// u.r/u.s, so a widget never has to know the display DPI.
// ---------------------------------------------------------------------------

func (u *natUI) fillRound(c *walk.Canvas, col walk.Color, r walk.Rectangle, rad float64) {
	b := u.brush(col)
	if b == nil {
		return
	}
	defer b.Dispose()
	_ = c.FillRoundedRectanglePixels(b, r, walk.Size{Width: u.s(rad), Height: u.s(rad)})
}

func (u *natUI) strokeRound(c *walk.Canvas, col walk.Color, r walk.Rectangle, rad float64) {
	p := u.pen(col)
	if p == nil {
		return
	}
	defer p.Dispose()
	_ = c.DrawRoundedRectanglePixels(p, r, walk.Size{Width: u.s(rad), Height: u.s(rad)})
}

func (u *natUI) fillRect(c *walk.Canvas, col walk.Color, r walk.Rectangle) {
	b := u.brush(col)
	if b == nil {
		return
	}
	defer b.Dispose()
	_ = c.FillRectanglePixels(b, r)
}

// brush hands back a solid brush or nil. A nil result must never reach a paint
// call: GDI does run out of handles, and a nil brush used to turn one failed
// allocation into a nil-pointer panic that closed the window mid-connect.
func (u *natUI) brush(col walk.Color) *walk.SolidColorBrush {
	b, err := walk.NewSolidColorBrush(col)
	if err != nil {
		return nil
	}
	return b
}

func (u *natUI) pen(col walk.Color) *walk.CosmeticPen {
	p, err := walk.NewCosmeticPen(walk.PenSolid, col)
	if err != nil {
		return nil
	}
	return p
}

// penW is a thick pen: width is in 1/96", which at this app's DPI is one
// design pixel. Icons, the ring around the connect button and the traffic
// curves all need strokes a cosmetic (always 1px) pen draws invisibly thin.
//
// The brush is disposed here: GeometricPen only remembers the colour values
// (logbrush builds a LOGBRUSH from them, no handle), so keeping the brush alive
// just leaked one GDI handle per thick stroke. At sixteen repaints a second
// that exhausted the process's handle quota in well under a minute.
func (u *natUI) penW(col walk.Color, w float64) *walk.GeometricPen {
	b := u.brush(col)
	if b == nil {
		return nil
	}
	defer b.Dispose()
	p, err := walk.NewGeometricPen(walk.PenSolid, int(w+0.5), b)
	if err != nil {
		return nil
	}
	return p
}

// shadowRound is the drop shadow under the cards: a stack of concentric
// rounded rectangles blending from the shadow tint back to the surface, which
// is what GDI+ (no blur, no alpha in Color) can do.
//
// Kept deliberately faint — on a light grey canvas macOS cards are separated by
// a hairline and a 2-3% shadow, not by the heavy blue halo the old mock used.
func (u *natUI) shadowRound(c *walk.Canvas, r walk.Rectangle, rad float64, tint walk.Color, base walk.Color) {
	for i := 3; i >= 1; i-- {
		d := float64(i)
		sr := walk.Rectangle{
			X:      r.X - u.s(d*0.5),
			Y:      r.Y - u.s(d*0.1),
			Width:  r.Width + u.s(d*1.0),
			Height: r.Height + u.s(d*1.2),
		}
		u.fillRound(c, mix(base, tint, 0.16/float64(i+1)), sr, rad+d)
	}
}

// circleStrokeW is a thick circle outline (the connect button's concentric
// rings, the rate badges).
func (u *natUI) circleStrokeW(c *walk.Canvas, col walk.Color, cx, cy, r, width float64) {
	p := u.penW(col, width)
	if p == nil {
		return
	}
	defer p.Dispose()
	if err := c.DrawEllipsePixels(p, u.r(cx-r, cy-r, 2*r, 2*r)); err != nil {
		// fall through: a failed decorative stroke must not break the frame
		_ = err
	}
}

// polylineW draws a smooth polyline with a thick pen.
func (u *natUI) polylineW(c *walk.Canvas, col walk.Color, pts []walk.Point, width float64) {
	if len(pts) < 2 {
		return
	}
	p := u.penW(col, width)
	if p == nil {
		return
	}
	defer p.Dispose()
	_ = c.DrawPolylinePixels(p, pts)
}

// arcW draws the open circle of the power glyph: an arc from a1 to a2 degrees
// (0 = 3 o'clock) sampled as a polyline, because there is no arc primitive.
func (u *natUI) arcW(c *walk.Canvas, col walk.Color, cx, cy, r, width, a1, a2 float64) {
	const steps = 40
	pts := make([]walk.Point, 0, steps+1)
	for i := 0; i <= steps; i++ {
		a := (a1 + (a2-a1)*float64(i)/float64(steps)) * math.Pi / 180
		pts = append(pts, u.p(cx+math.Cos(a)*r, cy+math.Sin(a)*r))
	}
	u.polylineW(c, col, pts, width)
}

// powerGlyph is the connect button's power mark, drawn with the same thick
// stroke as its ring so it stays legible at any size. The thin 1px version was
// the "icon nearly invisible" bug: at 200% DPI a cosmetic pen is one device
// pixel, which disappears against the gradient fill.
func (u *natUI) powerGlyph(c *walk.Canvas, cx, cy, size float64, col walk.Color) {
	r := size * 0.36
	w := size * 0.13
	// Stem: a filled bar through the gap at the top of the ring.
	u.fillRound(c, col, u.r(cx-w/2, cy-r-0.5, w, r*0.95), w/2)
	// Ring: 300° of circle, open at the top (from -60° to 240°).
	u.arcW(c, col, cx, cy, r, w, -62, 242)
}

// curveSamples turns a series into a dense, smoothed point list: Catmull-Rom
// interpolation between samples, which is what makes the sparkline read as a
// flowing curve instead of a zig-zag.
func (u *natUI) curveSamples(x, y, w, h float64, s []int64, peak int64, steps int) []walk.Point {
	if len(s) < 2 || peak <= 0 {
		return nil
	}
	px := func(i int) float64 { return x + w*float64(i)/float64(len(s)-1) }
	pts := make([]walk.Point, 0, len(s)*steps)
	at := func(i float64) (float64, float64) {
		i0 := int(math.Floor(i))
		if i0 < 0 {
			i0 = 0
		}
		if i0 > len(s)-2 {
			i0 = len(s) - 2
		}
		t := i - float64(i0)
		p0, p1, p2, p3 := i0-1, i0, i0+1, i0+2
		cl := func(i int) int {
			if i < 0 {
				return 0
			}
			if i > len(s)-1 {
				return len(s) - 1
			}
			return i
		}
		// Catmull-Rom on the y values with a uniform x step.
		v0, v1 := float64(s[cl(p0)]), float64(s[cl(p1)])
		v2, v3 := float64(s[cl(p2)]), float64(s[cl(p3)])
		yy := 0.5 * ((2 * v1) + (-v0+v2)*t + (2*v0-5*v1+4*v2-v3)*t*t + (-v0+3*v1-3*v2+v3)*t*t*t) / 1.0
		val := yy
		if val < 0 {
			val = 0
		}
		xx := px(cl(p1)) + (px(cl(p2))-px(cl(p1)))*t
		return xx, y + h - val/float64(peak)*h
	}
	for i := 0; i <= (len(s)-1)*steps; i++ {
		fx := float64(i) / float64(steps)
		xx, yy := at(fx)
		pts = append(pts, u.p(xx, yy))
	}
	return pts
}

// curveFill shades the area under a curve with a very light tint by painting
// thin columns from the curve down to the baseline — GDI+ has no alpha here,
// so the "low opacity" of the mock is a colour mixed toward the card.
func (u *natUI) curveFill(c *walk.Canvas, pts []walk.Point, baseline float64, col walk.Color, step float64) {
	for i := 0; i+1 < len(pts); i++ {
		x := u.ux(pts[i].X)
		yy := u.uy(pts[i].Y)
		if baseline <= yy {
			continue
		}
		u.fillRect(c, col, u.r(x, yy, step+0.6, baseline-yy))
	}
}

// hline is the one-pixel separator used inside cards and under tabs.
func (u *natUI) hline(c *walk.Canvas, x, y, w float64, col walk.Color) {
	u.fillRect(c, col, u.r(x, y, w, 1))
}

// circleFill / circleStroke build the round shapes: the connect button, status
// dots, avatars and the signal rings. They are separate from fillRound because
// a circle takes a diameter, not a corner radius.
func (u *natUI) circleFill(c *walk.Canvas, col walk.Color, cx, cy, r float64) {
	b := u.brush(col)
	if b == nil {
		return
	}
	defer b.Dispose()
	_ = c.FillEllipsePixels(b, u.r(cx-r, cy-r, 2*r, 2*r))
}

// ellipseFill is circleFill with independent radii, for the wallpaper's soft
// landscape banks (they are wide and flat, not round).
func (u *natUI) ellipseFill(c *walk.Canvas, col walk.Color, cx, cy, ew, eh float64) {
	b := u.brush(col)
	if b == nil {
		return
	}
	defer b.Dispose()
	_ = c.FillEllipsePixels(b, u.r(cx-ew, cy-eh, 2*ew, 2*eh))
}

// softEllipse paints a blurred-looking blob: a stack of nested ellipses whose
// colour fades toward the rim. GDI+ has no blur and no alpha in a solid brush,
// so blending each ring toward the surface colour is how the mock's out-of-focus
// hills are reproduced.
func (u *natUI) softEllipse(c *walk.Canvas, base, toward walk.Color, cx, cy, ew, eh, strength float64) {
	// Many thin rings, mixed from the *local* surface colour toward the
	// highlight: the outermost ring has to be exactly the surface, or the
	// shape's rim paints a darker halo and the "blur" shows up as a hard arc
	// (which is what a wash based on th.window does over a lighter gradient).
	const steps = 26
	for i := steps; i >= 1; i-- {
		t := float64(i) / float64(steps)
		f := strength * (1 - t) * (1 - t)
		if f <= 0.012 {
			continue
		}
		u.ellipseFill(c, mix(base, toward, f),
			cx, cy, ew*(0.55+0.45*t), eh*(0.55+0.45*t))
	}
}

// glowPx paints a soft coloured glow (design units): nested ellipses whose
// colour fades from the surface toward col. Unlike softEllipse (which fades to
// white), this tints the glow, so the dark canvas gets a green/cyan aurora and
// the light canvas a faint wash of the same hue.
func (u *natUI) glowPx(c *walk.Canvas, base walk.Color, cx, cy, ew, eh float64, col walk.Color, strength float64) {
	const steps = 24
	for i := steps; i >= 1; i-- {
		t := float64(i) / float64(steps)
		f := strength * (1 - t) * (1 - t)
		if f <= 0.01 {
			continue
		}
		u.ellipseFill(c, mix(base, col, f), cx, cy, ew*(0.5+0.5*t), eh*(0.5+0.5*t))
	}
}

// glowFall is the analytic falloff of glowPx at a point: the innermost ring
// covering it. wallpaperAt uses it to reproduce the painted surface colour.
func glowFall(strength, x, y, cx, cy, ew, eh float64) float64 {
	d := math.Hypot((x-cx)/ew, (y-cy)/eh)
	if d >= 1 {
		return 0
	}
	t := 2*d - 1
	if t < 0 {
		t = 0
	}
	return strength * (1 - t) * (1 - t)
}

func (u *natUI) circleStroke(c *walk.Canvas, col walk.Color, cx, cy, r float64) {
	p := u.pen(col)
	if p == nil {
		return
	}
	defer p.Dispose()
	_ = c.DrawEllipsePixels(p, u.r(cx-r, cy-r, 2*r, 2*r))
}

// ring draws a thick circle as "outer disc minus inner disc". A cosmetic pen is
// always one pixel wide, so this is how a heavy ring is drawn without a
// geometric pen.
func (u *natUI) ring(c *walk.Canvas, col, inner walk.Color, cx, cy, r, width float64) {
	u.circleFill(c, col, cx, cy, r)
	u.circleFill(c, inner, cx, cy, r-width)
}

func (u *natUI) line(c *walk.Canvas, col walk.Color, x1, y1, x2, y2 float64) {
	p := u.pen(col)
	if p == nil {
		return
	}
	defer p.Dispose()
	_ = c.DrawLinePixels(p, u.p(x1, y1), u.p(x2, y2))
}

func mix(a, b walk.Color, t float64) walk.Color {
	if t <= 0 {
		return a
	}
	if t >= 1 {
		return b
	}
	ar, ag, ab := a.R(), a.G(), a.B()
	br, bg, bb := b.R(), b.G(), b.B()
	return walk.RGB(
		byte(float64(ar)+(float64(br)-float64(ar))*t),
		byte(float64(ag)+(float64(bg)-float64(ag))*t),
		byte(float64(ab)+(float64(bb)-float64(ab))*t))
}

// ---------------------------------------------------------------------------
// Hexagon key (v5 connect button)
//
// GDI+ has no rounded-polygon primitive and no clip-to-path here, so the
// hexagon is sampled once per frame into a point list (quadratic corners) and
// every fill is a stack of horizontal rows whose exact left/right edges come
// from intersecting the scan line with that polygon. Strokes reuse the same
// point list as a closed polyline.
// ---------------------------------------------------------------------------

// hexDesign samples a pointy-top hexagon with rounded corners in design units.
// cut is how far each corner is trimmed along its two edges.
func hexDesign(cx, cy, R, cut float64) [][2]float64 {
	var vert [6][2]float64
	for i := range vert {
		a := (-90 + float64(i)*60) * math.Pi / 180
		vert[i] = [2]float64{cx + R*math.Cos(a), cy + R*math.Sin(a)}
	}
	toward := func(a, b [2]float64) [2]float64 {
		dx, dy := b[0]-a[0], b[1]-a[1]
		L := math.Hypot(dx, dy)
		return [2]float64{a[0] + dx/L*cut, a[1] + dy/L*cut}
	}
	const cornerSteps = 6
	pts := make([][2]float64, 0, 6*(cornerSteps+1))
	for i := 0; i < 6; i++ {
		v := vert[i]
		a := toward(v, vert[(i+5)%6])
		b := toward(v, vert[(i+1)%6])
		for s := 0; s <= cornerSteps; s++ {
			t := float64(s) / cornerSteps
			u1 := 1 - t
			pts = append(pts, [2]float64{
				u1*u1*a[0] + 2*u1*t*v[0] + t*t*b[0],
				u1*u1*a[1] + 2*u1*t*v[1] + t*t*b[1],
			})
		}
	}
	return pts
}

// hexVerts are the six sharp vertices, for the node dots on the outer ring.
func hexVerts(cx, cy, R float64) [][2]float64 {
	pts := make([][2]float64, 6)
	for i := range pts {
		a := (-90 + float64(i)*60) * math.Pi / 180
		pts[i] = [2]float64{cx + R*math.Cos(a), cy + R*math.Sin(a)}
	}
	return pts
}

// hexPoints is hexDesign in device pixels, ready for polyline strokes.
func (u *natUI) hexPoints(cx, cy, R, cut float64) []walk.Point {
	d := hexDesign(cx, cy, R, cut)
	pts := make([]walk.Point, len(d))
	for i, p := range d {
		pts[i] = u.p(p[0], p[1])
	}
	return pts
}

// hexSpan intersects a horizontal scan line with the sampled polygon.
func hexSpan(pts [][2]float64, y float64) (float64, float64, bool) {
	xl, xr := math.MaxFloat64, -math.MaxFloat64
	for i := range pts {
		a, b := pts[i], pts[(i+1)%len(pts)]
		if (a[1] <= y && b[1] > y) || (b[1] <= y && a[1] > y) {
			x := a[0] + (y-a[1])/(b[1]-a[1])*(b[0]-a[0])
			if x < xl {
				xl = x
			}
			if x > xr {
				xr = x
			}
		}
	}
	if xl > xr {
		return 0, 0, false
	}
	return xl, xr, true
}

// hexStroke outlines the sampled hexagon with a weighted closed polyline.
func (u *natUI) hexStroke(c *walk.Canvas, col walk.Color, pts []walk.Point, width float64) {
	closed := make([]walk.Point, len(pts)+1)
	copy(closed, pts)
	closed[len(pts)] = pts[0]
	u.polylineW(c, col, closed, width)
}

// hexFillGrad fills the hexagon with a top-to-bottom blend, one exact-width row
// at a time so the rounded corners stay clean without a clip path.
func (u *natUI) hexFillGrad(c *walk.Canvas, pts [][2]float64, from, to walk.Color, cy, R float64) {
	step := math.Max(1.0, R/48)
	for y := cy - R; y < cy+R; y += step {
		xl, xr, ok := hexSpan(pts, y+step/2)
		if !ok {
			continue
		}
		t := (y + step/2 - (cy - R)) / (2 * R)
		u.fillRect(c, mix(from, to, t), u.r(xl, y, xr-xl, step+0.4))
	}
}

// hexScan paints the connecting scan band: a horizontal light stripe sweeping
// down the hexagon, each row blended over the local gradient colour.
func (u *natUI) hexScan(c *walk.Canvas, pts [][2]float64, from, to walk.Color, cy, R, bandY, bandH float64) {
	const step = 1.5
	for y := bandY; y < bandY+bandH; y += step {
		xl, xr, ok := hexSpan(pts, y+step/2)
		if !ok {
			continue
		}
		t := (y - bandY) / bandH
		a := 0.34 * (1 - math.Abs(2*t-1))
		row := (y + step/2 - (cy - R)) / (2 * R)
		u.fillRect(c, mix(mix(from, to, row), rx(255, 255, 255), a), u.r(xl, y, xr-xl, step+0.4))
	}
}

// hexBracket is one side handle: a cubic bow bulging away from the key, with
// round caps faked by end dots. side is -1 (left) or +1 (right).
func (u *natUI) hexBracket(c *walk.Canvas, col walk.Color, cx, cy, R, side, width float64) {
	x0 := cx + side*R*1.13
	y0, y1 := cy-R*0.28, cy+R*0.28
	bx := x0 + side*R*0.09
	const steps = 16
	pts := make([]walk.Point, 0, steps+1)
	for i := 0; i <= steps; i++ {
		t := float64(i) / steps
		u1 := 1 - t
		x := u1*u1*u1*x0 + 3*u1*u1*t*bx + 3*u1*t*t*bx + t*t*t*x0
		y := u1*u1*u1*y0 + 3*u1*u1*t*(y0+R*0.10) + 3*u1*t*t*(y1-R*0.10) + t*t*t*y1
		pts = append(pts, u.p(x, y))
	}
	u.polylineW(c, col, pts, width)
	u.circleFill(c, col, x0, y0, width/2)
	u.circleFill(c, col, x0, y1, width/2)
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

func (u *natUI) text(c *walk.Canvas, s string, f *walk.Font, col walk.Color, r walk.Rectangle, fmtFlag walk.DrawTextFormat) {
	_ = c.DrawTextPixels(s, f, col, r, fmtFlag|walk.TextNoPrefix)
}

func (u *natUI) textL(c *walk.Canvas, s string, f *walk.Font, col walk.Color, r walk.Rectangle) {
	u.text(c, s, f, col, r, walk.TextSingleLine|walk.TextVCenter|walk.TextLeft|walk.TextEndEllipsis)
}

func (u *natUI) textR(c *walk.Canvas, s string, f *walk.Font, col walk.Color, r walk.Rectangle) {
	u.text(c, s, f, col, r, walk.TextSingleLine|walk.TextVCenter|walk.TextRight)
}

func (u *natUI) textC(c *walk.Canvas, s string, f *walk.Font, col walk.Color, r walk.Rectangle) {
	u.text(c, s, f, col, r, walk.TextSingleLine|walk.TextVCenter|walk.TextCenter)
}

// txt draws a single left-aligned line at (x, y) with the given height.
func (u *natUI) txt(c *walk.Canvas, x, y, w, h float64, s string, f *walk.Font, col walk.Color) {
	u.textL(c, s, f, col, u.r(x, y, w, h))
}

// ---------------------------------------------------------------------------
// Icons
//
// Drawn from primitives rather than shipped as images: there is no icon font in
// the build, and a dozen shapes is cheaper than a resource pipeline.
// ---------------------------------------------------------------------------

func (u *natUI) icon(c *walk.Canvas, kind string, x, y, size float64, col walk.Color) {
	s := size
	switch kind {
	case "home":
		// Roof: two lines meeting at the top; body: a rounded box under it.
		u.line(c, col, x, y+s*0.46, x+s*0.5, y+s*0.10)
		u.line(c, col, x+s*0.5, y+s*0.10, x+s, y+s*0.46)
		u.strokeRound(c, col, u.r(x+s*0.16, y+s*0.44, s*0.68, s*0.46), 2)
		u.line(c, col, x+s*0.44, y+s*0.90, x+s*0.44, y+s*0.66)
		u.line(c, col, x+s*0.56, y+s*0.90, x+s*0.56, y+s*0.66)
	case "nodes":
		// A stack of server rows.
		for i := 0; i < 3; i++ {
			yy := y + s*0.12 + float64(i)*s*0.30
			u.strokeRound(c, col, u.r(x+s*0.06, yy, s*0.88, s*0.22), 2)
			u.circleFill(c, col, x+s*0.22, yy+s*0.11, s*0.045)
		}
	case "rules":
		// Shield outline with a check inside.
		u.line(c, col, x+s*0.10, y+s*0.22, x+s*0.90, y+s*0.22)
		u.strokeRound(c, col, u.r(x+s*0.10, y+s*0.14, s*0.80, s*0.52), 3)
		u.line(c, col, x+s*0.36, y+s*0.44, x+s*0.47, y+s*0.58)
		u.line(c, col, x+s*0.47, y+s*0.58, x+s*0.68, y+s*0.32)
	case "gear", "settings":
		// A gear outline: ring, hub and eight teeth. Drawn with weighted
		// strokes so it survives 20px on a 200% display.
		u.circleStrokeW(c, col, x+s*0.5, y+s*0.5, s*0.29, 1.6)
		u.circleStrokeW(c, col, x+s*0.5, y+s*0.5, s*0.12, 1.5)
		for i := 0; i < 8; i++ {
			a := float64(i) * math.Pi / 4
			cs, sn := math.Cos(a), math.Sin(a)
			u.thickLine(c, col,
				x+s*0.5+cs*s*0.29, y+s*0.5+sn*s*0.29,
				x+s*0.5+cs*s*0.42, y+s*0.5+sn*s*0.42, 1.8)
		}
	case "logs":
		for i := 0; i < 3; i++ {
			yy := y + s*0.18 + float64(i)*s*0.30
			u.circleFill(c, col, x+s*0.10, yy, s*0.055)
			u.line(c, col, x+s*0.28, yy, x+s*0.94, yy)
		}
	case "info":
		u.circleStrokeW(c, col, x+s*0.5, y+s*0.5, s*0.4, 1.6)
		u.circleFill(c, col, x+s*0.5, y+s*0.30, s*0.055)
		u.thickLine(c, col, x+s*0.5, y+s*0.44, x+s*0.5, y+s*0.72, 1.7)
	case "close":
		u.line(c, col, x+s*0.18, y+s*0.18, x+s*0.82, y+s*0.82)
		u.line(c, col, x+s*0.82, y+s*0.18, x+s*0.18, y+s*0.82)
	case "search":
		u.circleStroke(c, col, x+s*0.42, y+s*0.42, s*0.32)
		u.line(c, col, x+s*0.66, y+s*0.66, x+s*0.94, y+s*0.94)
	case "refresh":
		u.circleStroke(c, col, x+s*0.5, y+s*0.52, s*0.34)
		u.line(c, col, x+s*0.62, y+s*0.10, x+s*0.86, y+s*0.20)
		u.line(c, col, x+s*0.62, y+s*0.10, x+s*0.58, y+s*0.34)
	case "chevron":
		u.thickLine(c, col, x+s*0.18, y+s*0.34, x+s*0.50, y+s*0.66, 1.8)
		u.thickLine(c, col, x+s*0.50, y+s*0.66, x+s*0.82, y+s*0.34, 1.8)
	case "power":
		// Bold glyph: the thin 1px ring was invisible against the gradient.
		u.powerGlyph(c, x+s*0.5, y+s*0.5, s, col)
	case "globe":
		u.circleStrokeW(c, col, x+s*0.5, y+s*0.5, s*0.4, 1.6)
		u.thickLine(c, col, x+s*0.10, y+s*0.5, x+s*0.90, y+s*0.5, 1.6)
		u.circleStrokeW(c, col, x+s*0.5, y+s*0.5, s*0.18, 1.6)
	case "shield":
		// A real shield outline: straight shoulders and a pointed foot. The old
		// version (a rounded box with a tick) read as a checkbox at 22px, which
		// is the wrong signal for the protocol selector.
		u.thickLine(c, col, x+s*0.14, y+s*0.26, x+s*0.50, y+s*0.10, 1.7)
		u.thickLine(c, col, x+s*0.50, y+s*0.10, x+s*0.86, y+s*0.26, 1.7)
		u.thickLine(c, col, x+s*0.14, y+s*0.26, x+s*0.19, y+s*0.60, 1.7)
		u.thickLine(c, col, x+s*0.19, y+s*0.60, x+s*0.50, y+s*0.90, 1.7)
		u.thickLine(c, col, x+s*0.86, y+s*0.26, x+s*0.81, y+s*0.60, 1.7)
		u.thickLine(c, col, x+s*0.81, y+s*0.60, x+s*0.50, y+s*0.90, 1.7)
	case "bolt":
		u.line(c, col, x+s*0.56, y+s*0.06, x+s*0.32, y+s*0.52)
		u.line(c, col, x+s*0.32, y+s*0.52, x+s*0.52, y+s*0.52)
		u.line(c, col, x+s*0.52, y+s*0.52, x+s*0.44, y+s*0.94)
		u.line(c, col, x+s*0.44, y+s*0.94, x+s*0.68, y+s*0.44)
		u.line(c, col, x+s*0.68, y+s*0.44, x+s*0.48, y+s*0.44)
		u.line(c, col, x+s*0.48, y+s*0.44, x+s*0.56, y+s*0.06)
	case "sun":
		u.circleStroke(c, col, x+s*0.5, y+s*0.5, s*0.22)
		for i := 0; i < 8; i++ {
			a := float64(i) * math.Pi / 4
			cs, sn := math.Cos(a), math.Sin(a)
			u.line(c, col,
				x+s*0.5+cs*s*0.34, y+s*0.5+sn*s*0.34,
				x+s*0.5+cs*s*0.46, y+s*0.5+sn*s*0.46)
		}
	case "moon":
		u.circleFill(c, col, x+s*0.5, y+s*0.5, s*0.36)
		u.circleFill(c, th.card, x+s*0.66, y+s*0.36, s*0.34)
	case "monitor":
		u.strokeRound(c, col, u.r(x+s*0.06, y+s*0.14, s*0.88, s*0.58), 2)
		u.line(c, col, x+s*0.34, y+s*0.88, x+s*0.66, y+s*0.88)
		u.line(c, col, x+s*0.5, y+s*0.72, x+s*0.5, y+s*0.88)
	case "star":
		// Four-point sparkle: cheap, and unmistakably a favourite marker.
		u.line(c, col, x+s*0.5, y+s*0.08, x+s*0.5, y+s*0.92)
		u.line(c, col, x+s*0.08, y+s*0.5, x+s*0.92, y+s*0.5)
		u.line(c, col, x+s*0.22, y+s*0.22, x+s*0.78, y+s*0.78)
		u.line(c, col, x+s*0.78, y+s*0.22, x+s*0.22, y+s*0.78)
	case "pin":
		u.circleFill(c, col, x+s*0.5, y+s*0.36, s*0.20)
		u.line(c, col, x+s*0.5, y+s*0.56, x+s*0.5, y+s*0.92)
	case "grid":
		for i := 0; i < 2; i++ {
			for j := 0; j < 2; j++ {
				u.strokeRound(c, col, u.r(x+s*0.10+float64(i)*s*0.46, y+s*0.10+float64(j)*s*0.46, s*0.36, s*0.36), 2)
			}
		}
	case "list":
		u.line(c, col, x+s*0.08, y+s*0.24, x+s*0.92, y+s*0.24)
		u.line(c, col, x+s*0.08, y+s*0.50, x+s*0.92, y+s*0.50)
		u.line(c, col, x+s*0.08, y+s*0.76, x+s*0.92, y+s*0.76)
	case "link":
		u.circleStroke(c, col, x+s*0.32, y+s*0.5, s*0.22)
		u.circleStroke(c, col, x+s*0.68, y+s*0.5, s*0.22)
		u.line(c, col, x+s*0.32, y+s*0.5, x+s*0.68, y+s*0.5)
	case "folder":
		u.strokeRound(c, col, u.r(x+s*0.08, y+s*0.22, s*0.84, s*0.62), 2)
		u.line(c, col, x+s*0.08, y+s*0.38, x+s*0.40, y+s*0.38)
		u.line(c, col, x+s*0.40, y+s*0.38, x+s*0.46, y+s*0.24)
	case "clock":
		u.circleStrokeW(c, col, x+s*0.5, y+s*0.5, s*0.4, 1.6)
		u.thickLine(c, col, x+s*0.5, y+s*0.28, x+s*0.5, y+s*0.52, 1.6)
		u.thickLine(c, col, x+s*0.5, y+s*0.52, x+s*0.68, y+s*0.62, 1.6)
	case "up":
		u.thickLine(c, col, x+s*0.5, y+s*0.14, x+s*0.5, y+s*0.86, 1.8)
		u.thickLine(c, col, x+s*0.26, y+s*0.40, x+s*0.5, y+s*0.14, 1.8)
		u.thickLine(c, col, x+s*0.74, y+s*0.40, x+s*0.5, y+s*0.14, 1.8)
	case "down":
		u.thickLine(c, col, x+s*0.5, y+s*0.14, x+s*0.5, y+s*0.86, 1.8)
		u.thickLine(c, col, x+s*0.26, y+s*0.60, x+s*0.5, y+s*0.86, 1.8)
		u.thickLine(c, col, x+s*0.74, y+s*0.60, x+s*0.5, y+s*0.86, 1.8)
	case "copy":
		u.thickRound(c, col, u.r(x+s*0.34, y+s*0.34, s*0.52, s*0.52), 2, 1.6)
		u.thickRound(c, col, u.r(x+s*0.10, y+s*0.10, s*0.52, s*0.52), 2, 1.6)
	case "edit":
		// A pencil: slanted shaft closed into a nib at the lower-left.
		u.thickLine(c, col, x+s*0.20, y+s*0.80, x+s*0.68, y+s*0.32, 1.7)
		u.thickLine(c, col, x+s*0.68, y+s*0.32, x+s*0.82, y+s*0.46, 1.7)
		u.thickLine(c, col, x+s*0.82, y+s*0.46, x+s*0.34, y+s*0.94, 1.7)
		u.thickLine(c, col, x+s*0.20, y+s*0.80, x+s*0.34, y+s*0.94, 1.7)
	case "trash":
		// A bin: lid with a handle, body, and two ribs.
		u.thickLine(c, col, x+s*0.16, y+s*0.26, x+s*0.84, y+s*0.26, 1.6)
		u.thickLine(c, col, x+s*0.38, y+s*0.26, x+s*0.38, y+s*0.13, 1.5)
		u.thickLine(c, col, x+s*0.62, y+s*0.26, x+s*0.62, y+s*0.13, 1.5)
		u.thickLine(c, col, x+s*0.38, y+s*0.13, x+s*0.62, y+s*0.13, 1.5)
		u.strokeRound(c, col, u.r(x+s*0.25, y+s*0.26, s*0.50, s*0.64), 2)
		u.line(c, col, x+s*0.43, y+s*0.40, x+s*0.43, y+s*0.78)
		u.line(c, col, x+s*0.57, y+s*0.40, x+s*0.57, y+s*0.78)
	}
}

// thickLine is the straight line with a weighted stroke: the small icons read
// at 14px only when they are not a single hairline.
func (u *natUI) thickLine(c *walk.Canvas, col walk.Color, x1, y1, x2, y2, w float64) {
	p := u.penW(col, w)
	if p == nil {
		return
	}
	defer p.Dispose()
	_ = c.DrawLinePixels(p, u.p(x1, y1), u.p(x2, y2))
}

// thickRound is strokeRound with a weighted pen.
func (u *natUI) thickRound(c *walk.Canvas, col walk.Color, r walk.Rectangle, rad, w float64) {
	p := u.penW(col, w)
	if p == nil {
		return
	}
	defer p.Dispose()
	_ = c.DrawRoundedRectanglePixels(p, r, walk.Size{Width: u.s(rad), Height: u.s(rad)})
}

// statusDot is the small coloured bullet used by pills and rows.
func (u *natUI) statusDot(c *walk.Canvas, cx, cy, r float64, col walk.Color) {
	u.circleFill(c, col, cx, cy, r)
}

// bars renders the four-bar signal strength for a latency in milliseconds. It
// is a coarse quality hint, not a measurement: <60ms all four, then one bar per
// 80ms.
func (u *natUI) bars(c *walk.Canvas, x, y float64, ms int64, col walk.Color) {
	lit := 0
	switch {
	case ms <= 0:
		lit = 0
	case ms < 60:
		lit = 4
	case ms < 120:
		lit = 3
	case ms < 200:
		lit = 2
	default:
		lit = 1
	}
	for i := 0; i < 4; i++ {
		h := 4.5 + float64(i)*3.5
		cx := x + float64(i)*5.5
		cy := y + (16-h)/2
		r := u.r(cx, cy, 3, h)
		if i < lit {
			u.fillRound(c, col, r, 1.5)
		} else {
			u.fillRound(c, th.toggleOff, r, 1.5)
		}
	}
}

// spinner draws a rotating ring of fading dots — the "测试中" indicator. The
// head dot is full colour and the trail fades to the toggle-off grey; u.m.spin
// advances the head so the ring appears to turn. Only dots are used (no arc
// primitive), each a disposed circleFill, so it adds no lasting GDI handles.
func (u *natUI) spinner(c *walk.Canvas, cx, cy, r float64, col walk.Color) {
	const n = 10
	head := u.m.spin % n
	if head < 0 {
		head += n
	}
	for i := 0; i < n; i++ {
		a := float64(i) * 2 * math.Pi / n
		d := (head - i + n) % n
		t := 1.0 - float64(d)/float64(n)
		if t < 0.15 {
			t = 0.15
		}
		u.circleFill(c, mix(th.toggleOff, col, t), cx+r*math.Cos(a), cy+r*math.Sin(a), r*0.20+0.5)
	}
}

// ---------------------------------------------------------------------------
// Widgets
// ---------------------------------------------------------------------------

// card draws a titled surface and returns the y where its content starts.
func (u *natUI) card(c *walk.Canvas, x, y, w, h float64, title string) float64 {
	u.cardPlain(c, x, y, w, h)
	if title == "" {
		return y + 12
	}
	u.txt(c, x+16, y+13, w-32, 20, title, u.f.f11b, th.text)
	return y + 40
}

// cardPlain is a card without a title (or with one drawn by the caller): a
// frosted blue panel from the palette, a bright 1px rim (glass edges catch the
// light, they are not outlined in grey), and a soft shadow on the page.
func (u *natUI) cardPlain(c *walk.Canvas, x, y, w, h float64) {
	u.shadowRound(c, u.r(x, y, w, h), cardRadius, shadowTint(), th.window)
	u.fillRound(c, th.card, u.r(x, y, w, h), cardRadius)
	u.strokeRound(c, th.line2, u.r(x+0.5, y+0.5, w-1, h-1), cardRadius)
}

// shadowTint is the colour a card's shadow blends toward. Light: a slightly
// deeper tint of the blue canvas, so the shadow looks like the same material
// rather than grey dirt. Dark: black, or the "shadow" would turn into a glow.
func shadowTint() walk.Color {
	if th.window.R() < 128 {
		return mix(th.window, rx(0, 0, 0), 0.45)
	}
	return mix(th.window, rx(86, 108, 140), 0.30)
}

// rowToggle is a labelled switch with an optional second line. A disabled row
// is drawn muted so it reads as unavailable rather than broken; the caller
// supplies a sub line explaining why (see paintSetExit).
func (u *natUI) rowToggle(c *walk.Canvas, x, y, w float64, id, label, sub string, on, enabled bool) {
	lcol, scol := th.text, th.dim
	if !enabled {
		lcol, scol = th.faint, th.faint
	}
	lh := 20.0
	if sub != "" {
		lh = 34
		u.txt(c, x+16, y+1, w-80, 17, label, u.f.f10, lcol)
		u.txt(c, x+16, y+19, w-80, 14, sub, u.f.f8, scol)
	} else {
		u.txt(c, x+16, y+(38-lh)/2, w-80, lh, label, u.f.f10, lcol)
	}
	u.switchAt(c, id, x+w-16-44, y+6, on, enabled)
	if enabled {
		u.addSpot(id, u.r(x, y, w, 38), true)
	}
}

// switchAt draws the pill switch itself.
func (u *natUI) switchAt(c *walk.Canvas, id string, x, y float64, on, enabled bool) {
	track := u.r(x, y, 44, 26)
	col := th.toggleOff
	if on {
		col = th.accent
	}
	if !enabled {
		col = mix(col, th.card, 0.55)
	}
	u.fillRound(c, col, track, 13)
	knobX := x + 3
	if on {
		knobX = x + 44 - 26
	}
	u.circleFill(c, th.card, knobX+10, y+13, 10)
}

// rowEdit is a label with an editable value box; clicking it opens the text
// dialog, which is the only way this window accepts typing.
func (u *natUI) rowEdit(c *walk.Canvas, x, y, w float64, id, label, value, placeholder string) {
	u.rowEditState(c, x, y, w, id, label, value, placeholder, true)
}

// rowEditState is rowEdit with an enable flag: a field whose value no preset
// can honour is drawn muted and takes no clicks rather than opening a dialog
// that silently changes nothing.
func (u *natUI) rowEditState(c *walk.Canvas, x, y, w float64, id, label, value, placeholder string, enabled bool) {
	lcol := th.text
	if !enabled {
		lcol = th.faint
	}
	u.txt(c, x+16, y+8, w-260, 20, label, u.f.f10, lcol)
	box := u.r(x+w-16-228, y+4, 228, 30)
	u.fillRound(c, th.input, box, ctrlRadius)
	if u.m.hover == id && enabled {
		u.strokeRound(c, th.accentLine, box, ctrlRadius)
	}
	disp, col := value, th.text
	if disp == "" {
		disp, col = placeholder, th.faint
	}
	if !enabled {
		disp, col = value, th.faint
		if disp == "" {
			disp = placeholder
		}
	}
	u.textL(c, disp, u.f.f10, col, u.r(x+w-16-228+10, y+4, 208, 30))
	if enabled {
		u.addSpot(id, box, true)
	}
}

// popupBelow places a dropdown popup under its anchor, flipping above when the
// list would run off the bottom of the window. One helper for every dropdown,
// so none of them can poke past the frame.
func popupBelow(ay, ah, ph float64) float64 {
	py := ay + ah + 6
	if py+ph > 686 {
		py = ay - 6 - ph
	}
	if py < 4 {
		py = 4
	}
	return py
}

// chipAt draws one chip and registers its hit area. Returns its width.
func (u *natUI) chipAt(c *walk.Canvas, id, label string, x, y float64, active, enabled bool) float64 {
	w := chipWidth(label)
	r := u.r(x, y, w, 28)
	bg, fg, line := th.chip, th.chipText, th.line
	if active {
		bg, fg, line = th.accentSoft, th.accent, th.accentLine
	} else if u.m.hover == id && enabled {
		bg = th.cardHover
	}
	if !enabled {
		fg = th.faint
	}
	u.fillRound(c, bg, r, ctrlRadius)
	if active {
		u.strokeRound(c, line, r, ctrlRadius)
	}
	u.textC(c, label, u.f.f9, fg, r)
	if enabled {
		u.addSpot(id, r, true)
	}
	return w
}

// chipWidth estimates a chip's width in design units. Deliberately not measured
// from the canvas: MeasureTextPixels answers in device pixels while every
// coordinate here is in the design grid, so mixing them doubles widths on a
// high-DPI display.
func chipWidth(label string) float64 {
	w := 0.0
	for _, r := range label {
		switch {
		case r > 0x2E80: // CJK and fullwidth forms
			w += 13.4
		case r >= 'A' && r <= 'Z':
			w += 7.4
		default:
			w += 6.8
		}
	}
	if w < 20 {
		w = 20
	}
	return w + 24
}

// button is the filled (primary) or outlined action button.
func (u *natUI) button(c *walk.Canvas, x, y, w, h float64, id, label string, primary, enabled bool) {
	r := u.r(x, y, w, h)
	bg, fg, line := th.card, th.text, th.line
	if primary {
		bg, fg, line = th.accent, th.accentText, th.accent
	} else if u.m.hover == id && enabled {
		bg = th.cardHover
	}
	if !enabled {
		// Still legible: on this palette a disabled button that fades to the
		// faint tint disappears entirely.
		bg, fg = mix(bg, th.card, 0.55), th.dim
	}
	u.fillRound(c, bg, r, ctrlRadius)
	if !primary || !enabled {
		u.strokeRound(c, line, r, ctrlRadius)
	}
	u.textC(c, label, u.f.f10b, fg, r)
	if enabled {
		u.addSpot(id, r, true)
	}
}

// iconButton is a square, borderless button holding one icon.
func (u *natUI) iconButton(c *walk.Canvas, x, y, size float64, id, kind string, enabled bool) {
	r := u.r(x, y, size, size)
	if u.m.hover == id && enabled {
		u.fillRound(c, th.cardHover, r, 12)
	}
	col := th.dim
	if !enabled {
		col = th.faint
	}
	u.icon(c, kind, x+size*0.22, y+size*0.22, size*0.56, col)
	if enabled {
		u.addSpot(id, r, true)
	}
}

// inputBox draws a read-only-looking field. Clicking it opens the text dialog;
// the field itself never takes focus.
func (u *natUI) inputBox(c *walk.Canvas, x, y, w, h float64, id, value, placeholder string) {
	r := u.r(x, y, w, h)
	u.fillRound(c, th.input, r, ctrlRadius)
	if u.m.hover == id {
		u.strokeRound(c, th.accentLine, r, ctrlRadius)
	}
	disp, col := value, th.text
	if disp == "" {
		disp, col = placeholder, th.faint
	}
	u.textL(c, disp, u.f.f10, col, u.r(x+10, y, w-20, h))
	u.addSpot(id, r, true)
}

// subtabs is the underlined tab bar used inside the rules, settings and log
// pages. It returns nothing: the active tab is whatever cur says.
func (u *natUI) subtabs(c *walk.Canvas, x, y float64, prefix string, ids, labels []string, cur string) float64 {
	cx := x
	for i := range ids {
		w := chipWidth(labels[i]) + 8
		r := u.r(cx, y, w, 30)
		active := cur == ids[i]
		col := th.dim
		if active {
			col = th.accent
		} else if u.m.hover == prefix+ids[i] {
			col = th.text
		}
		u.textC(c, labels[i], u.f.f12b, col, r)
		if active {
			u.fillRound(c, th.accent, u.r(cx+(w-26)/2, y+30, 26, 3), 1.5)
		}
		u.addSpot(prefix+ids[i], r, true)
		cx += w + 6
	}
	return cx
}

// flagChip draws a flag and the country code from an ISO alpha-2 code.
func (u *natUI) flagChip(c *walk.Canvas, x, y, w, h float64, cc string) {
	u.fillRound(c, th.input, u.r(x, y, w, h), 7)
	u.drawFlag(c, x+2, y+2, w-4, h-4, cc)
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }
