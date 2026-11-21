//go:build windows

package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"sync"

	_ "embed"

	"github.com/lxn/walk"
)

// logoPNG is the app logo, embedded so the brand mark and the window/taskbar
// icon never depend on a file next to the exe. Regenerated from the source art
// by tools/mklogo (assets/logo.png, 512px — enough for the brand at any DPI).
//
//go:embed assets/logo.png
var logoPNG []byte

var (
	logoOnce sync.Once
	logoSrc  image.Image
)

// logoImage decodes the embedded PNG once. Returns nil if it cannot be decoded,
// in which case callers fall back to the vector brand mark.
func logoImage() image.Image {
	logoOnce.Do(func() {
		if img, err := png.Decode(bytes.NewReader(logoPNG)); err == nil {
			logoSrc = img
		}
	})
	return logoSrc
}

// logoAspect is the brand mark's height/width. The approved art is 512x321, so
// every placement derives its height from the width it is given instead of
// assuming a square (the old square asset stretched the XH mark).
const logoAspect = 321.0 / 512.0

// drawLogo paints the logo at a design-grid rect (x, y, size), replacing the
// vector brand mark. size is the WIDTH; the height follows the mark's aspect.
// The image is area-averaged down to the exact device size and cached, so a
// HiDPI window gets a crisp logo without re-scaling per frame.
func (u *natUI) drawLogo(c *walk.Canvas, x, y, size float64) {
	px := u.s(size)
	bmp := logoBitmap(px)
	if bmp == nil {
		// Embedded logo unavailable: keep the old vector mark rather than a hole.
		u.icon(c, "shield", x, y, size*logoAspect, th.accent)
		return
	}
	_ = c.DrawImagePixels(bmp, walk.Point{X: u.sx(x), Y: u.sy(y)})
}

var (
	logoBmpMu sync.Mutex
	logoBmps  = map[int]*walk.Bitmap{}
)

// logoBitmap returns the logo scaled to px wide (height follows logoAspect),
// cached per width.
func logoBitmap(px int) *walk.Bitmap {
	if px <= 0 {
		return nil
	}
	logoBmpMu.Lock()
	defer logoBmpMu.Unlock()
	if b, ok := logoBmps[px]; ok {
		return b
	}
	src := logoImage()
	if src == nil {
		return nil
	}
	h := int(float64(px)*logoAspect + 0.5)
	if h < 1 {
		h = 1
	}
	b, err := walk.NewBitmapFromImage(resizeImage(src, px, h))
	if err != nil {
		return nil
	}
	logoBmps[px] = b
	return b
}

// disposeLogo releases the cached brand bitmaps' GDI handles at window close.
func disposeLogo() {
	logoBmpMu.Lock()
	defer logoBmpMu.Unlock()
	for _, b := range logoBmps {
		b.Dispose()
	}
	logoBmps = map[int]*walk.Bitmap{}
}

// setWindowIcon builds the running window's icon from the embedded logo, so the
// taskbar button, Alt-Tab and title bar show it. It is applied via SetIcon
// (WM_SETICON), which takes precedence over the window-class icon — rsrc puts
// the exe's group icon at a resource ID walk does not look for, so relying on
// the class icon alone would leave the generic Windows icon on the taskbar.
func (u *natUI) setWindowIcon() {
	if u.mw == nil {
		return
	}
	src := logoImage()
	if src == nil {
		return
	}
	// 64px downscales cleanly to every size SetIcon asks for (16/32/48) and is
	// cheap for GDI to resample; no need to hand it the full 512px asset. The
	// mark is wider than tall, so it is centred in a square transparent canvas
	// rather than stretched to fill one.
	icon, err := walk.NewIconFromImage(logoSquare(64))
	if err != nil {
		return
	}
	_ = u.mw.SetIcon(icon)
}

// logoSquare fits the brand mark inside a size×size transparent square,
// preserving its aspect, for the window/taskbar icon.
func logoSquare(size int) *image.NRGBA {
	dst := image.NewNRGBA(image.Rect(0, 0, size, size))
	src := logoImage()
	if src == nil {
		return dst
	}
	sb := src.Bounds()
	w, h := size, size
	if sb.Dx()*h > sb.Dy()*w {
		h = size * sb.Dy() / sb.Dx()
	} else {
		w = size * sb.Dx() / sb.Dy()
	}
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	scaled := resizeImage(src, w, h)
	ox, oy := (size-w)/2, (size-h)/2
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			dst.SetNRGBA(ox+x, oy+y, scaled.NRGBAAt(x, y))
		}
	}
	return dst
}

// resizeImage area-averages src down to exactly w×h. Box averaging keeps a
// large source clean when reduced to icon sizes; averaging non-premultiplied
// NRGBA is good enough for an essentially-opaque logo and keeps the rounded
// corners' alpha.
func resizeImage(src image.Image, w, h int) *image.NRGBA {
	dst := image.NewNRGBA(image.Rect(0, 0, w, h))
	sb := src.Bounds()
	sw, sh := sb.Dx(), sb.Dy()
	for dy := 0; dy < h; dy++ {
		sy0 := dy * sh / h
		sy1 := (dy + 1) * sh / h
		if sy1 <= sy0 {
			sy1 = sy0 + 1
		}
		for dx := 0; dx < w; dx++ {
			sx0 := dx * sw / w
			sx1 := (dx + 1) * sw / w
			if sx1 <= sx0 {
				sx1 = sx0 + 1
			}
			var r, g, b, a, n uint32
			for sy := sy0; sy < sy1 && sy < sh; sy++ {
				for sx := sx0; sx < sx1 && sx < sw; sx++ {
					c := color.NRGBAModel.Convert(src.At(sb.Min.X+sx, sb.Min.Y+sy)).(color.NRGBA)
					r += uint32(c.R)
					g += uint32(c.G)
					b += uint32(c.B)
					a += uint32(c.A)
					n++
				}
			}
			if n > 0 {
				dst.SetNRGBA(dx, dy, color.NRGBA{R: uint8(r / n), G: uint8(g / n), B: uint8(b / n), A: uint8(a / n)})
			}
		}
	}
	return dst
}
