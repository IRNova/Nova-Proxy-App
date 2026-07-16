package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/png"
	"io"
	"os"
	"path/filepath"
)

// ICOHeader represents the ICO file header
type ICOHeader struct {
	Reserved uint16
	Type     uint16 // 1 = icon
	Count    uint16
}

// ICOEntry represents an entry in the ICO directory
type ICOEntry struct {
	Width      uint8
	Height     uint8
	ColorCount uint8
	Reserved   uint8
	Planes     uint16
	BPP        uint16
	Size       uint32
	Offset     uint32
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: icogen <input.png> [output.ico]")
		os.Exit(1)
	}

	input := os.Args[1]
	output := "icon.ico"
	if len(os.Args) >= 3 {
		output = os.Args[2]
	}

	// Read PNG
	f, err := os.Open(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening %s: %v\n", input, err)
		os.Exit(1)
	}
	defer f.Close()

	src, err := png.Decode(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding PNG: %v\n", err)
		os.Exit(1)
	}

	// Supported sizes for ICO (256 → 0 in ICO format)
	sizes := []int{16, 24, 32, 48, 64, 128}

	// Build icon data for each size
	type iconData struct {
		entry ICOEntry
		data  []byte
	}
	var icons []iconData
	var offset uint32 = uint32(binary.Size(ICOHeader{})) + uint32(len(sizes))*uint32(binary.Size(ICOEntry{}))

	for _, size := range sizes {
		resized := resizeImage(src, size)
		pngData, err := encodePNG(resized)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding size %d: %v\n", size, err)
			continue
		}

		var w, h uint8
		if size >= 256 {
			w = 0 // 0 means 256 in ICO
			h = 0
		} else {
			w = uint8(size)
			h = uint8(size)
		}

		icons = append(icons, iconData{
			entry: ICOEntry{
				Width:      w,
				Height:     h,
				ColorCount: 0,
				Reserved:   0,
				Planes:     1,
				BPP:        32,
				Size:       uint32(len(pngData)),
				Offset:     offset,
			},
			data: pngData,
		})
		offset += uint32(len(pngData))
	}

	// Write ICO file
	out, err := os.Create(output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating %s: %v\n", output, err)
		os.Exit(1)
	}
	defer out.Close()

	// Write header
	binary.Write(out, binary.LittleEndian, ICOHeader{
		Reserved: 0,
		Type:     1,
		Count:    uint16(len(icons)),
	})

	// Write directory entries
	for _, icon := range icons {
		binary.Write(out, binary.LittleEndian, icon.entry)
	}

	// Write image data
	for _, icon := range icons {
		out.Write(icon.data)
	}

	abs, _ := filepath.Abs(output)
	fmt.Printf("ICO created: %s (%d sizes)\n", abs, len(icons))
}

func resizeImage(src image.Image, size int) image.Image {
	bounds := src.Bounds()
	if bounds.Dx() == size && bounds.Dy() == size {
		return src
	}

	dst := image.NewRGBA(image.Rect(0, 0, size, size))
	scaleX := float64(bounds.Dx()) / float64(size)
	scaleY := float64(bounds.Dy()) / float64(size)

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			sx := int(float64(x) * scaleX)
			sy := int(float64(y) * scaleY)
			if sx >= bounds.Dx() {
				sx = bounds.Dx() - 1
			}
			if sy >= bounds.Dy() {
				sy = bounds.Dy() - 1
			}
			dst.Set(x, y, src.At(sx, sy))
		}
	}
	return dst
}

func encodePNG(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	// For ICO, PNG data includes the PNG header + IHDR + IDAT + IEND
	// This is the standard way to store 32bpp icons with alpha
	w := io.Writer(&buf)
	if err := png.Encode(w, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
