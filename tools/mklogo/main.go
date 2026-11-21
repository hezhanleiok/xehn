// Command mklogo regenerates the GUI logo assets from a high-resolution source
// PNG. The source is the borderless brand mark (any aspect); it is not required
// to be square. It produces two artifacts:
//
//   - a downscaled PNG for go:embed (default assets/logo.png) that preserves the
//     mark's aspect (longest edge = embed): the in-app brand mark renders from it
//     directly, so it must stay borderless and transparent;
//   - a multi-size Windows .ico (16/24/32/48/64/256, PNG-compressed frames) that
//     rsrc embeds into the exe so Explorer shows it as the program icon. Each
//     frame pads the mark into a transparent square so the icon is not stretched.
//
// Usage (from the xehn directory):
//
//	go run ./tools/mklogo -src ../../ui-mockups/logo-mark.png -png assets/logo.png -ico logo.ico
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
)

func main() {
	src := flag.String("src", "../../ui-mockups/logo-mark.png", "source PNG (borderless brand mark, any aspect, high-res)")
	outPNG := flag.String("png", "assets/logo.png", "output downscaled PNG for go:embed")
	outICO := flag.String("ico", "logo.ico", "output multi-size .ico for rsrc")
	embed := flag.Int("embed", 512, "longest edge of the embedded PNG")
	flag.Parse()

	img, err := loadPNG(*src)
	if err != nil {
		fatal(err)
	}
	b := img.Bounds()
	sw, sh := b.Dx(), b.Dy()
	scale := float64(*embed) / float64(max(sw, sh))
	ow, oh := int(float64(sw)*scale+0.5), int(float64(sh)*scale+0.5)
	if ow < 1 {
		ow = 1
	}
	if oh < 1 {
		oh = 1
	}

	if err := writePNG(*outPNG, resize(img, ow, oh)); err != nil {
		fatal(err)
	}
	fmt.Printf("wrote %s (%dx%d)\n", *outPNG, ow, oh)

	sizes := []int{16, 24, 32, 48, 64, 256}
	frames := make([]frame, 0, len(sizes))
	for _, s := range sizes {
		var buf bytes.Buffer
		if err := png.Encode(&buf, fitSquare(img, s)); err != nil {
			fatal(err)
		}
		frames = append(frames, frame{size: s, png: buf.Bytes()})
	}
	if err := writeICO(*outICO, frames); err != nil {
		fatal(err)
	}
	fmt.Printf("wrote %s (frames %v)\n", *outICO, sizes)
}

type frame struct {
	size int
	png  []byte
}

func loadPNG(path string) (image.Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return png.Decode(f)
}

func writePNG(path string, img image.Image) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, img)
}

// writeICO builds an ICO whose frames are PNG-compressed (supported on Vista+;
// rsrc copies the frame bytes verbatim into RT_ICON, so no BMP fallback needed).
func writeICO(path string, frames []frame) error {
	var hdr bytes.Buffer
	// ICONDIR
	_ = binary.Write(&hdr, binary.LittleEndian, uint16(0)) // reserved
	_ = binary.Write(&hdr, binary.LittleEndian, uint16(1)) // type: icon
	_ = binary.Write(&hdr, binary.LittleEndian, uint16(len(frames)))
	offset := 6 + 16*len(frames)
	for _, fr := range frames {
		_ = binary.Write(&hdr, binary.LittleEndian, byte(icoDim(fr.size))) // width  (0 => 256)
		_ = binary.Write(&hdr, binary.LittleEndian, byte(icoDim(fr.size))) // height (0 => 256)
		_ = binary.Write(&hdr, binary.LittleEndian, byte(0))               // color count
		_ = binary.Write(&hdr, binary.LittleEndian, byte(0))               // reserved
		_ = binary.Write(&hdr, binary.LittleEndian, uint16(1))             // planes
		_ = binary.Write(&hdr, binary.LittleEndian, uint16(32))            // bit count
		_ = binary.Write(&hdr, binary.LittleEndian, uint32(len(fr.png)))   // bytes in res
		_ = binary.Write(&hdr, binary.LittleEndian, uint32(offset))        // image offset
		offset += len(fr.png)
	}
	out := &bytes.Buffer{}
	out.Write(hdr.Bytes())
	for _, fr := range frames {
		out.Write(fr.png)
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}

func icoDim(v int) int {
	if v >= 256 {
		return 0
	}
	return v
}

// resize area-averages src down to exactly w×h. Box averaging keeps a large
// source (2880px) clean when reduced to icon sizes; non-premultiplied NRGBA is
// good enough for an essentially-opaque logo and preserves the rounded corners.
func resize(src image.Image, w, h int) *image.NRGBA {
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

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "mklogo:", err)
	os.Exit(1)
}

// fitSquare fits the mark inside a size×size transparent square, preserving its
// aspect, for an ICO frame. Windows icons are square; padding (rather than
// stretching) keeps the wider-than-tall XH mark undistorted at every size.
func fitSquare(src image.Image, size int) *image.NRGBA {
	dst := image.NewNRGBA(image.Rect(0, 0, size, size))
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
	scaled := resize(src, w, h)
	ox, oy := (size-w)/2, (size-h)/2
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			dst.SetNRGBA(ox+x, oy+y, scaled.NRGBAAt(x, y))
		}
	}
	return dst
}
