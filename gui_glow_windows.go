//go:build windows

package main

import (
	"fmt"
	"math"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
)

// glowSprite is a premultiplied-alpha falloff tile. The connect key's halo and
// body glow have to composite over the wallpaper (dark aurora, light wave
// bands), and GDI solid brushes carry no alpha: mixing toward one surface
// colour paints a visible disc wherever the local background differs from that
// base. AlphaBlend with a baked falloff is exact at every pixel. Breathing
// modulates only SourceConstantAlpha, so tiles rebuild on colour/size/shape
// change alone.
type glowSprite struct {
	dc   win.HDC
	bmp  win.HBITMAP
	old  win.HGDIOBJ
	size int32
}

func (u *natUI) freeGlowSprites() {
	for _, s := range u.glowSpr {
		win.SelectObject(s.dc, s.old)
		win.DeleteObject(win.HGDIOBJ(s.bmp))
		win.DeleteDC(s.dc)
	}
	u.glowSpr = nil
}

// glowSpriteFor bakes a tile of px device pixels. hexR == 0 gives the radial
// halo falloff; hexR > 0 gives a rounded-hexagon fringe that is full strength
// at the body edge (hexR as a fraction of the tile half) and zero at the rim.
func (u *natUI) glowSpriteFor(col walk.Color, px int32, hexR float64) *glowSprite {
	key := fmt.Sprintf("%06x/%d/%.4f", uint32(col.R())<<16|uint32(col.G())<<8|uint32(col.B()), px, hexR)
	if s := u.glowSpr[key]; s != nil {
		return s
	}
	if px < 4 {
		return nil
	}
	if len(u.glowSpr) > 8 {
		u.freeGlowSprites()
	}
	dc := win.CreateCompatibleDC(0)
	if dc == 0 {
		return nil
	}
	bi := win.BITMAPINFOHEADER{
		BiSize:        uint32(unsafe.Sizeof(win.BITMAPINFOHEADER{})),
		BiWidth:       px,
		BiHeight:      -px,
		BiPlanes:      1,
		BiBitCount:    32,
		BiCompression: win.BI_RGB,
	}
	var bits unsafe.Pointer
	bmp := win.CreateDIBSection(dc, &bi, win.DIB_RGB_COLORS, &bits, 0, 0)
	if bmp == 0 || bits == nil {
		win.DeleteDC(dc)
		return nil
	}
	old := win.SelectObject(dc, win.HGDIOBJ(bmp))
	pix := (*[1 << 28]byte)(bits)[: px*px*4 : px*px*4]
	half := float64(px) / 2
	cr, cg, cb := float64(col.R()), float64(col.G()), float64(col.B())
	fringe := 1 - hexR
	i := 0
	for y := int32(0); y < px; y++ {
		dy := math.Abs(float64(y)+0.5-half) / half
		for x := int32(0); x < px; x++ {
			dx := math.Abs(float64(x)+0.5-half) / half
			var d float64
			if hexR > 0 {
				d = math.Max(dx/(0.8660254*hexR), (dy+dx*0.5773503)/hexR)
			} else {
				d = math.Sqrt(dx*dx + dy*dy)
			}
			a := 0.0
			if hexR > 0 {
				if d < 1 {
					t := (1 - d) / fringe
					if t > 1 {
						t = 1
					}
					a = t * t
				}
			} else if d < 1 {
				t := 2*d - 1
				if t < 0 {
					t = 0
				}
				a = (1 - t) * (1 - t)
			}
			pix[i] = byte(cb*a + 0.5)
			pix[i+1] = byte(cg*a + 0.5)
			pix[i+2] = byte(cr*a + 0.5)
			pix[i+3] = byte(a*255 + 0.5)
			i += 4
		}
	}
	if u.glowSpr == nil {
		u.glowSpr = map[string]*glowSprite{}
	}
	s := &glowSprite{dc: dc, bmp: bmp, old: old, size: px}
	u.glowSpr[key] = s
	return s
}

// glowAlpha composites a breathing glow over whatever the wallpaper painted
// under the key, so no rim disc appears on either theme's layered background.
func (u *natUI) glowAlpha(c *walk.Canvas, cx, cy, ew, eh float64, col walk.Color, strength, hexR float64) {
	r := u.r(cx-ew, cy-eh, 2*ew, 2*eh)
	spr := u.glowSpriteFor(col, int32(r.Width), hexR)
	if spr == nil {
		u.glowPx(c, u.wallpaperAt(cx, cy+capH), cx, cy, ew, eh, col, strength)
		return
	}
	a := strength
	if a < 0 {
		a = 0
	}
	if a > 1 {
		a = 1
	}
	ok := win.AlphaBlend(c.HDC(), int32(r.X), int32(r.Y), int32(r.Width), int32(r.Height),
		spr.dc, 0, 0, spr.size, spr.size,
		win.BLENDFUNCTION{SourceConstantAlpha: byte(a*255 + 0.5), AlphaFormat: win.AC_SRC_ALPHA})
	if !ok {
		u.glowPx(c, u.wallpaperAt(cx, cy+capH), cx, cy, ew, eh, col, strength)
	}
}