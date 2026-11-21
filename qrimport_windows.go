//go:build windows

package main

// 本文件自包含：二维码图片解码、剪贴板文本/图片读取、导入文件选择。
// 不引用主包其它文件的任何类型或函数（tr/u.m/stageMsg 等），所有失败都以
// error 返回，由调用方决定如何记日志或提示 UI，本文件不向 UI 输出任何内容。

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"golang.org/x/sys/windows"
)

// ---- Windows 剪贴板 / 全局内存的 Win32 绑定 ----
// 说明：walk 的 ClipboardService 只有 Clear/ContainsText/Text/SetText，
// 没有任何图片相关 API；x/sys/windows 也未导出 OpenClipboard 等封装，
// 而 lxn/win 的剪贴板句柄/常量签名不便核实。因此这里用 x/sys/windows 的
// LazyDLL 直接绑定 user32/kernel32，函数签名完全自控，最不易因第三方包
// 版本差异导致编译失败。
var (
	// gui_chrome_windows.go already owns the package-level name `user32`.
	qrUser32   = windows.NewLazySystemDLL("user32.dll")
	qrKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procOpenClipboard              = qrUser32.NewProc("OpenClipboard")
	procCloseClipboard             = qrUser32.NewProc("CloseClipboard")
	procGetClipboardData           = qrUser32.NewProc("GetClipboardData")
	procIsClipboardFormatAvailable = qrUser32.NewProc("IsClipboardFormatAvailable")
	procGlobalLock                 = qrKernel32.NewProc("GlobalLock")
	procGlobalUnlock               = qrKernel32.NewProc("GlobalUnlock")
	procGlobalSize                 = qrKernel32.NewProc("GlobalSize")
)

// 剪贴板格式与 DIB 压缩方式常量（数值来自 Win32 SDK）。
// 取独立前缀，避免与主包里可能存在的同名标识符冲突。
const (
	clipFmtBitmap = 2  // CF_BITMAP：GDI 位图句柄(DDB)，不是可锁定的像素内存
	clipFmtDIB    = 8  // CF_DIB：一段以 BITMAPINFOHEADER 开头的 DIB 数据
	clipFmtDIBV5  = 17 // CF_DIBV5：以 BITMAPV5HEADER(124B) 开头的 DIB 数据
	dibRGB        = 0  // BI_RGB
	dibBitfields  = 3  // BI_BITFIELDS
)

// DecodeQRImage 用 gozxing 解码一张内存图像，返回二维码文本。
// NewBinaryBitmapFromImage 内部已采用 HybridBinarizer 做二值化，
// 因此这里无需再手工灰度/二值化。
func DecodeQRImage(img image.Image) (string, error) {
	if img == nil {
		return "", fmt.Errorf("二维码图像为空")
	}
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", fmt.Errorf("二维码图像二值化失败: %w", err)
	}
	result, err := qrcode.NewQRCodeReader().Decode(bmp, nil)
	if err != nil {
		return "", fmt.Errorf("未能在图像中识别到二维码: %w", err)
	}
	return result.GetText(), nil
}

// DecodeQRFile 读取 png/jpeg/gif/bmp 文件并解码其中的二维码。
// 标准库没有 bmp 解码器；BMP 文件 = 14 字节 BITMAPFILEHEADER + 一段 DIB，
// 与剪贴板 CF_DIB 布局一致，故复用同一套 DIB 解析。
func DecodeQRFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("读取导入文件 %q 失败: %w", path, err)
	}
	// 先按文件内容嗅探 png/jpeg/gif（三者已由上方空白 import 注册进 image）。
	if img, _, derr := image.Decode(bytes.NewReader(raw)); derr == nil {
		return DecodeQRImage(img)
	}
	// 再按 "BM" 文件头处理 bmp。
	if len(raw) >= 14 && raw[0] == 'B' && raw[1] == 'M' {
		img, berr := decodeBMPBytes(raw)
		if berr != nil {
			return "", fmt.Errorf("解析 BMP 图片失败: %w", berr)
		}
		return DecodeQRImage(img)
	}
	return "", fmt.Errorf("不支持的导入图片格式（仅支持 png/jpeg/gif/bmp）")
}

// decodeBMPBytes 解析一个完整的 BMP 文件字节。
func decodeBMPBytes(raw []byte) (image.Image, error) {
	// BITMAPFILEHEADER 的 bfOffBits 位于偏移 10，给出像素数据相对文件头的偏移。
	offBits := int(binary.LittleEndian.Uint32(raw[10:14]))
	if offBits < 14 || offBits > len(raw) {
		return nil, fmt.Errorf("BMP bfOffBits=%d 越界", offBits)
	}
	// 第 14 字节起即 BITMAPINFOHEADER(DIB 头)；像素偏移换算成相对 DIB 的偏移。
	return dibToNRGBA(raw[14:], offBits-14)
}

// ReadClipboardText 与 setClipboardText 对称：剪贴板常被截图工具/管理器
// 短暂占用，Text() 会偶发失败，故重试 8 次、每次间隔 30ms。
// 返回去掉首尾空白的文本，空白文本视为失败。
func ReadClipboardText() (string, error) {
	var lastErr error
	for i := 0; i < 8; i++ {
		text, err := walk.Clipboard().Text()
		if err == nil {
			if t := strings.TrimSpace(text); t != "" {
				return t, nil
			}
			lastErr = fmt.Errorf("剪贴板文本为空")
		} else {
			lastErr = err
		}
		time.Sleep(30 * time.Millisecond)
	}
	return "", fmt.Errorf("读取剪贴板文本失败: %w", lastErr)
}

// ReadClipboardImage 从 Win32 剪贴板读取图片，返回 image.Image。
// 坑与取舍：
//   - 只能读 CF_DIB / CF_DIBV5，它们是可 GlobalLock 的 DIB 内存块；
//     CF_BITMAP 是 GDI 位图句柄(DDB)，无法直接取像素，只能给出明确错误。
//   - 必须在 OpenClipboard 成功后再判格式并读数据，且成对 CloseClipboard。
//   - DIB 像素默认"自下而上"、每行 4 字节对齐、通道顺序为 BGR(A)，
//     这些细节统一交给 dibToNRGBA 处理。
func ReadClipboardImage() (image.Image, error) {
	if r, _, _ := procOpenClipboard.Call(0); r == 0 {
		return nil, fmt.Errorf("OpenClipboard 失败（剪贴板可能被其它程序占用）")
	}
	defer procCloseClipboard.Call()

	var cf uint32
	switch {
	case hasClipboardFormat(clipFmtDIB):
		cf = clipFmtDIB
	case hasClipboardFormat(clipFmtDIBV5):
		cf = clipFmtDIBV5
	case hasClipboardFormat(clipFmtBitmap):
		return nil, fmt.Errorf("剪贴板仅含 CF_BITMAP(DDB) 格式，无法直接解析像素；请把截图另存为文件后用「文件导入」")
	default:
		return nil, fmt.Errorf("剪贴板中没有可用的图像格式（CF_DIB/CF_DIBV5）")
	}

	h, _, _ := procGetClipboardData.Call(uintptr(cf))
	if h == 0 {
		return nil, fmt.Errorf("GetClipboardData(格式 %d) 失败", cf)
	}
	ptr, _, _ := procGlobalLock.Call(h)
	if ptr == 0 {
		return nil, fmt.Errorf("GlobalLock 剪贴板图像内存失败")
	}
	defer procGlobalUnlock.Call(h)
	size, _, _ := procGlobalSize.Call(h)
	if size == 0 {
		return nil, fmt.Errorf("剪贴板 DIB 数据为空")
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), int(size))
	return dibToNRGBA(data, -1)
}

func hasClipboardFormat(cf uint32) bool {
	r, _, _ := procIsClipboardFormatAvailable.Call(uintptr(cf))
	return r != 0
}

// dibToNRGBA 解析从 BITMAPINFOHEADER 开始的 DIB 字节为 image.NRGBA。
// forcedPixelOffset >= 0 时直接采用（BMP 文件用 bfOffBits）；< 0 时自行推算
// （剪贴板 DIB：头 + 可选掩码 + 调色板）。
// 仅支持 biSize>=40、24/32 位、BI_RGB/BI_BITFIELDS，其余返回明确错误。
func dibToNRGBA(data []byte, forcedPixelOffset int) (image.Image, error) {
	if len(data) < 40 {
		return nil, fmt.Errorf("DIB 头过短（%d 字节，需要 >=40）", len(data))
	}
	u32 := func(o int) uint32 { return binary.LittleEndian.Uint32(data[o : o+4]) }
	i32 := func(o int) int32 { return int32(binary.LittleEndian.Uint32(data[o : o+4])) }
	u16 := func(o int) uint16 { return binary.LittleEndian.Uint16(data[o : o+2]) }

	headerSize := int(u32(0)) // biSize
	width := int(i32(4))      // biWidth
	height := int(i32(8))     // biHeight
	planes := u16(12)         // biPlanes
	bitCount := int(u16(14))  // biBitCount
	compression := u32(16)    // biCompression
	clrUsed := u32(32)        // biClrUsed

	if headerSize < 40 {
		return nil, fmt.Errorf("不支持的 DIB 头 biSize=%d（需要 >=40）", headerSize)
	}
	if planes != 1 {
		return nil, fmt.Errorf("不支持的 DIB biPlanes=%d", planes)
	}
	if bitCount != 24 && bitCount != 32 {
		return nil, fmt.Errorf("仅支持 24/32 位 DIB，当前 biBitCount=%d", bitCount)
	}
	if compression != dibRGB && compression != dibBitfields {
		return nil, fmt.Errorf("不支持的 DIB 压缩方式 biCompression=%d（仅支持 BI_RGB/BI_BITFIELDS）", compression)
	}
	if width <= 0 || height == 0 {
		return nil, fmt.Errorf("非法的 DIB 尺寸 %dx%d", width, height)
	}
	// 坑：biHeight<0 表示"自上而下"，否则是默认的"自下而上"。
	topDown := false
	if height < 0 {
		topDown = true
		height = -height
	}

	pixelOffset := forcedPixelOffset
	if pixelOffset < 0 {
		pixelOffset = headerSize
		// biSize==40 的 BITMAPINFOHEADER + BI_BITFIELDS：3 个 DWORD 颜色掩码
		// 紧跟在头之后（占 12 字节）；V4/V5 头的掩码已在头内部，不再另加。
		if compression == dibBitfields && headerSize == 40 {
			pixelOffset += 12
		}
		// 调色板（RGBQUAD，每项 4 字节）；24/32 位通常为 0。
		pixelOffset += int(clrUsed) * 4
	}

	// 坑：DIB 每行按 4 字节对齐，不能直接按 width*bpp 步进。
	stride := ((width*bitCount + 31) / 32) * 4
	if pixelOffset < 0 || pixelOffset+stride*height > len(data) {
		return nil, fmt.Errorf("DIB 像素数据不完整（需要 %d 字节，实际 %d）",
			pixelOffset+stride*height, len(data))
	}

	bpp := bitCount / 8
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	for row := 0; row < height; row++ {
		y := row
		if !topDown {
			y = height - 1 - row // 自下而上：翻转行序
		}
		line := pixelOffset + row*stride
		for x := 0; x < width; x++ {
			p := line + x*bpp
			// 坑：DIB 通道顺序是 B,G,R(,A)，需交换成 R,G,B。
			b, g, r := data[p], data[p+1], data[p+2]
			// 坑：32 位 BI_RGB 的第 4 字节是保留字节（并非 alpha，常为 0）。
			// 若直接当成 alpha，整幅图会变成"全透明"，gozxing 会把它当白底
			// 而解不出二维码，因此强制设为不透明 0xff。
			di := y*img.Stride + x*4
			img.Pix[di], img.Pix[di+1], img.Pix[di+2], img.Pix[di+3] = r, g, b, 0xff
		}
	}
	return img, nil
}

// PickImportFile 弹出「打开文件」对话框，返回 (路径, 是否确认, 错误)。
// Filter 用 "描述|通配符" 成对书写，walk 会把 '|' 转成 NUL(\0) 交给 Win32；
// 同一项的多个扩展名用分号分隔。
func PickImportFile(owner walk.Form) (string, bool, error) {
	dlg := walk.FileDialog{
		Title: "导入订阅或节点",
		Filter: "订阅/配置文件 (*.yaml;*.yml;*.txt;*.conf)|*.yaml;*.yml;*.txt;*.conf|" +
			"二维码图片 (*.png;*.jpg;*.jpeg;*.bmp)|*.png;*.jpg;*.jpeg;*.bmp|" +
			"所有文件 (*.*)|*.*",
		InitialDirPath: "",
		ShowReadOnlyCB: false,
	}
	accepted, err := dlg.ShowOpen(owner)
	if err != nil {
		return "", false, err
	}
	if !accepted {
		return "", false, nil
	}
	return dlg.FilePath, true, nil
}

// ImportFromClipboard 返回 (内容, 来源, 错误)，来源为 "text" 或 "qr"。
// 优先取纯文本；无文本或文本为空时，退而尝试剪贴板图片里的二维码。
func ImportFromClipboard() (string, string, error) {
	var textErr error
	hasText, ctErr := walk.Clipboard().ContainsText()
	if hasText && ctErr == nil {
		if t, err := ReadClipboardText(); err == nil {
			return t, "text", nil
		} else {
			textErr = err
		}
	} else {
		textErr = fmt.Errorf("剪贴板不含文本 (%v)", ctErr)
	}

	img, imgErr := ReadClipboardImage()
	if imgErr != nil {
		return "", "", fmt.Errorf("从剪贴板导入失败（文本：%v；图片：%v）", textErr, imgErr)
	}
	code, qrErr := DecodeQRImage(img)
	if qrErr != nil {
		return "", "", fmt.Errorf("从剪贴板导入失败（文本：%v；二维码：%v）", textErr, qrErr)
	}
	return code, "qr", nil
}
