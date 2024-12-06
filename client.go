package http2

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"crypto/rand"

	"math/bits"
	"net"

	"net/textproto"

	"github.com/gospider007/ja3"
	"github.com/gospider007/tools"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2/hpack"
)

func http2asciiEqualFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if http2lower(s[i]) != http2lower(t[i]) {
			return false
		}
	}
	return true
}

// lower returns the ASCII lowercase version of b.
func http2lower(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// isASCIIPrint returns whether s is ASCII and printable according to
// https://tools.ietf.org/html/rfc20#section-4.2.
func http2isASCIIPrint(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// asciiToLower returns the lowercase version of s if s is ASCII and printable,
// and whether or not it was.
func http2asciiToLower(s string) (lower string, ok bool) {
	if !http2isASCIIPrint(s) {
		return "", false
	}
	return strings.ToLower(s), true
}

// An ErrCode is an unsigned 32-bit error code as defined in the HTTP/2 spec.
type errHttp2Code uint32

const (
	errHttp2CodeNo                 errHttp2Code = 0x0
	errHttp2CodeProtocol           errHttp2Code = 0x1
	errHttp2CodeInternal           errHttp2Code = 0x2
	errHttp2CodeFlowControl        errHttp2Code = 0x3
	errHttp2CodeSettingsTimeout    errHttp2Code = 0x4
	errHttp2CodeStreamClosed       errHttp2Code = 0x5
	errHttp2CodeFrameSize          errHttp2Code = 0x6
	errHttp2CodeRefusedStream      errHttp2Code = 0x7
	errHttp2CodeCancel             errHttp2Code = 0x8
	errHttp2CodeCompression        errHttp2Code = 0x9
	errHttp2CodeConnect            errHttp2Code = 0xa
	errHttp2CodeEnhanceYourCalm    errHttp2Code = 0xb
	errHttp2CodeInadequateSecurity errHttp2Code = 0xc
	errHttp2CodeHTTP11Required     errHttp2Code = 0xd
)

// ConnectionError is an error that results in the termination of the
// entire connection.
type http2ConnectionError errHttp2Code

func (e http2ConnectionError) Error() string {
	return fmt.Sprintf("connection error: %d", errHttp2Code(e))
}

var (
	errHttp2PseudoAfterRegular = errors.New("pseudo header field after regular")
)

// inflowMinRefresh is the minimum number of bytes we'll send for a
// flow control window update.
const http2inflowMinRefresh = 4 << 10

// inflow accounts for an inbound flow control window.
// It tracks both the latest window sent to the peer (used for enforcement)
// and the accumulated unsent window.
type http2inflow struct {
	avail  int32
	unsent int32
}

// init sets the initial window.
func (f *http2inflow) init(n int32) {
	f.avail = n
}

// add adds n bytes to the window, with a maximum window size of max,
// indicating that the peer can now send us more data.
// For example, the user read from a {Request,Response} body and consumed
// some of the buffered data, so the peer can now send more.
// It returns the number of bytes to send in a WINDOW_UPDATE frame to the peer.
// Window updates are accumulated and sent when the unsent capacity
// is at least inflowMinRefresh or will at least double the peer's available window.
func (f *http2inflow) add(n int) (connAdd int32) {
	if n < 0 {
		panic("negative update")
	}
	unsent := int64(f.unsent) + int64(n)
	// "A sender MUST NOT allow a flow-control window to exceed 2^31-1 octets."
	// RFC 7540 Section 6.9.1.
	const maxWindow = 1<<31 - 1
	if unsent+int64(f.avail) > maxWindow {
		panic("flow control update exceeds maximum window size")
	}
	f.unsent = int32(unsent)
	if f.unsent < http2inflowMinRefresh && f.unsent < f.avail {
		// If there aren't at least inflowMinRefresh bytes of window to send,
		// and this update won't at least double the window, buffer the update for later.
		return 0
	}
	f.avail += f.unsent
	f.unsent = 0
	return int32(unsent)
}

// takeInflows attempts to take n bytes from two inflows,
// typically connection-level and stream-level flows.
// It reports whether both windows have available capacity.
func http2takeInflows(f1, f2 *http2inflow, n uint32) bool {
	if n > uint32(f1.avail) || n > uint32(f2.avail) {
		return false
	}
	f1.avail -= int32(n)
	f2.avail -= int32(n)
	return true
}

// outflow is the outbound flow control window's size.
type http2outflow struct {
	_ http2incomparable

	// n is the number of DATA bytes we're allowed to send.
	// An outflow is kept both on a conn and a per-stream.
	n int32

	// conn points to the shared connection-level outflow that is
	// shared by all streams on that conn. It is nil for the outflow
	// that's on the conn directly.
	conn *http2outflow
}

func (f *http2outflow) setConnFlow(cf *http2outflow) { f.conn = cf }

func (f *http2outflow) available() int32 {
	n := f.n
	if f.conn != nil && f.conn.n < n {
		n = f.conn.n
	}
	return n
}

func (f *http2outflow) take(n int32) {
	if n > f.available() {
		panic("internal error: took too much")
	}
	f.n -= n
	if f.conn != nil {
		f.conn.n -= n
	}
}

// add adds n bytes (positive or negative) to the flow control window.
// It returns false if the sum would exceed 2^31-1.
func (f *http2outflow) add(n int32) bool {
	sum := f.n + n
	if (sum > n) == (f.n > 0) {
		f.n = sum
		return true
	}
	return false
}

const http2frameHeaderLen = 9

var http2padZeros = make([]byte, 255) // zeros for padding

// A FrameType is a registered frame type as defined in
// https://httpwg.org/specs/rfc7540.html#rfc.section.11.2
type http2FrameType uint8

const (
	http2FrameData         http2FrameType = 0x0
	http2FrameHeaders      http2FrameType = 0x1
	http2FramePriority     http2FrameType = 0x2
	http2FrameRSTStream    http2FrameType = 0x3
	http2FrameSettings     http2FrameType = 0x4
	http2FramePushPromise  http2FrameType = 0x5
	http2FramePing         http2FrameType = 0x6
	http2FrameGoAway       http2FrameType = 0x7
	http2FrameWindowUpdate http2FrameType = 0x8
	http2FrameContinuation http2FrameType = 0x9
)

var http2frameName = map[http2FrameType]string{
	http2FrameData:         "DATA",
	http2FrameHeaders:      "HEADERS",
	http2FramePriority:     "PRIORITY",
	http2FrameRSTStream:    "RST_STREAM",
	http2FrameSettings:     "SETTINGS",
	http2FramePushPromise:  "PUSH_PROMISE",
	http2FramePing:         "PING",
	http2FrameGoAway:       "GOAWAY",
	http2FrameWindowUpdate: "WINDOW_UPDATE",
	http2FrameContinuation: "CONTINUATION",
}

func (t http2FrameType) String() string {
	if s, ok := http2frameName[t]; ok {
		return s
	}
	return fmt.Sprintf("UNKNOWN_FRAME_TYPE_%d", uint8(t))
}

// Flags is a bitmask of HTTP/2 flags.
// The meaning of flags varies depending on the frame type.
type http2Flags uint8

// Has reports whether f contains all (0 or more) flags in v.
func (f http2Flags) Has(v http2Flags) bool {
	return (f & v) == v
}

// Frame-specific FrameHeader flag bits.
const (
	// Data Frame
	http2FlagDataEndStream http2Flags = 0x1
	http2FlagDataPadded    http2Flags = 0x8

	// Headers Frame
	http2FlagHeadersEndStream  http2Flags = 0x1
	http2FlagHeadersEndHeaders http2Flags = 0x4
	http2FlagHeadersPadded     http2Flags = 0x8
	http2FlagHeadersPriority   http2Flags = 0x20

	// Settings Frame
	http2FlagSettingsAck http2Flags = 0x1

	// Ping Frame
	http2FlagPingAck http2Flags = 0x1

	// Continuation Frame
	http2FlagContinuationEndHeaders http2Flags = 0x4

	http2FlagPushPromiseEndHeaders http2Flags = 0x4
	http2FlagPushPromisePadded     http2Flags = 0x8
)

var http2flagName = map[http2FrameType]map[http2Flags]string{
	http2FrameData: {
		http2FlagDataEndStream: "END_STREAM",
		http2FlagDataPadded:    "PADDED",
	},
	http2FrameHeaders: {
		http2FlagHeadersEndStream:  "END_STREAM",
		http2FlagHeadersEndHeaders: "END_HEADERS",
		http2FlagHeadersPadded:     "PADDED",
		http2FlagHeadersPriority:   "PRIORITY",
	},
	http2FrameSettings: {
		http2FlagSettingsAck: "ACK",
	},
	http2FramePing: {
		http2FlagPingAck: "ACK",
	},
	http2FrameContinuation: {
		http2FlagContinuationEndHeaders: "END_HEADERS",
	},
	http2FramePushPromise: {
		http2FlagPushPromiseEndHeaders: "END_HEADERS",
		http2FlagPushPromisePadded:     "PADDED",
	},
}

// a frameParser parses a frame given its FrameHeader and payload
// bytes. The length of payload will always equal fh.Length (which
// might be 0).
type http2frameParser func(fc *http2frameCache, fh http2FrameHeader, countError func(string), payload []byte) (http2Frame, error)

func http2parseHeadersFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (_ http2Frame, err error) {
	hf := &http2HeadersFrame{
		http2FrameHeader: fh,
	}
	if fh.StreamID == 0 {
		// HEADERS frames MUST be associated with a stream. If a HEADERS frame
		// is received whose stream identifier field is 0x0, the recipient MUST
		// respond with a connection error (Section 5.4.1) of type
		// PROTOCOL_ERROR.
		countError("frame_headers_zero_stream")
		return nil, errors.New("HEADERS frame with stream ID 0")
	}
	var padLength uint8
	if fh.Flags.Has(http2FlagHeadersPadded) {
		if p, padLength, err = http2readByte(p); err != nil {
			countError("frame_headers_pad_short")
			return
		}
	}
	if fh.Flags.Has(http2FlagHeadersPriority) {
		var v uint32
		p, v, err = http2readUint32(p)
		if err != nil {
			countError("frame_headers_prio_short")
			return nil, err
		}
		hf.Priority.StreamDep = v & 0x7fffffff
		hf.Priority.Exclusive = (v != hf.Priority.StreamDep) // high bit was set
		p, hf.Priority.Weight, err = http2readByte(p)
		if err != nil {
			countError("frame_headers_prio_weight_short")
			return nil, err
		}
	}
	if len(p)-int(padLength) < 0 {
		countError("frame_headers_pad_too_big")
		return nil, errors.New("frame_headers_pad_too_big")
	}
	hf.headerFragBuf = p[:len(p)-int(padLength)]
	return hf, nil
}

var http2frameParsers = map[http2FrameType]http2frameParser{
	http2FrameData:         http2parseDataFrame,
	http2FrameHeaders:      http2parseHeadersFrame,
	http2FramePriority:     http2parsePriorityFrame,
	http2FrameRSTStream:    http2parseRSTStreamFrame,
	http2FrameSettings:     http2parseSettingsFrame,
	http2FramePushPromise:  http2parsePushPromise,
	http2FramePing:         http2parsePingFrame,
	http2FrameGoAway:       http2parseGoAwayFrame,
	http2FrameWindowUpdate: http2parseWindowUpdateFrame,
	http2FrameContinuation: http2parseContinuationFrame,
}

func http2typeFrameParser(t http2FrameType) http2frameParser {
	if f := http2frameParsers[t]; f != nil {
		return f
	}
	return http2parseUnknownFrame
}

// A FrameHeader is the 9 byte header of all HTTP/2 frames.
//
// See https://httpwg.org/specs/rfc7540.html#FrameHeader
type http2FrameHeader struct {
	valid bool // caller can access []byte fields in the Frame

	// Type is the 1 byte frame type. There are ten standard frame
	// types, but extension frame types may be written by WriteRawFrame
	// and will be returned by ReadFrame (as UnknownFrame).
	Type http2FrameType

	// Flags are the 1 byte of 8 potential bit flags per frame.
	// They are specific to the frame type.
	Flags http2Flags

	// Length is the length of the frame, not including the 9 byte header.
	// The maximum size is one byte less than 16MB (uint24), but only
	// frames up to 16KB are allowed without peer agreement.
	Length uint32

	// StreamID is which stream this frame is for. Certain frames
	// are not stream-specific, in which case this field is 0.
	StreamID uint32
}

// Header returns h. It exists so FrameHeaders can be embedded in other
// specific frame types and implement the Frame interface.
func (h http2FrameHeader) Header() http2FrameHeader { return h }

func (h http2FrameHeader) String() string {
	var buf bytes.Buffer
	buf.WriteString("[FrameHeader ")
	h.writeDebug(&buf)
	buf.WriteByte(']')
	return buf.String()
}

func (h http2FrameHeader) writeDebug(buf *bytes.Buffer) {
	buf.WriteString(h.Type.String())
	if h.Flags != 0 {
		buf.WriteString(" flags=")
		set := 0
		for i := uint8(0); i < 8; i++ {
			if h.Flags&(1<<i) == 0 {
				continue
			}
			set++
			if set > 1 {
				buf.WriteByte('|')
			}
			name := http2flagName[h.Type][http2Flags(1<<i)]
			if name != "" {
				buf.WriteString(name)
			} else {
				fmt.Fprintf(buf, "0x%x", 1<<i)
			}
		}
	}
	if h.StreamID != 0 {
		fmt.Fprintf(buf, " stream=%d", h.StreamID)
	}
	fmt.Fprintf(buf, " len=%d", h.Length)
}

func (h *http2FrameHeader) checkValid() {
	if !h.valid {
		panic("Frame accessor called on non-owned Frame")
	}
}

func (h *http2FrameHeader) invalidate() { h.valid = false }

func http2readFrameHeader(buf []byte, r io.Reader) (http2FrameHeader, error) {
	_, err := io.ReadFull(r, buf[:http2frameHeaderLen])
	if err != nil {
		return http2FrameHeader{}, err
	}
	return http2FrameHeader{
		Length:   (uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2])),
		Type:     http2FrameType(buf[3]),
		Flags:    http2Flags(buf[4]),
		StreamID: binary.BigEndian.Uint32(buf[5:]) & (1<<31 - 1),
		valid:    true,
	}, nil
}

// A Frame is the base interface implemented by all frame types.
// Callers will generally type-assert the specific frame type:
// *HeadersFrame, *SettingsFrame, *WindowUpdateFrame, etc.
//
// Frames are only valid until the next call to Framer.ReadFrame.
type http2Frame interface {
	Header() http2FrameHeader

	// invalidate is called by Framer.ReadFrame to make this
	// frame's buffers as being invalid, since the subsequent
	// frame will reuse them.
	invalidate()
}

// A Framer reads and writes Frames.
type http2Framer struct {
	r         io.Reader
	lastFrame http2Frame
	errDetail error

	// countError is a non-nil func that's called on a frame parse
	// error with some unique error path token. It's initialized
	// from Transport.CountError or Server.CountError.
	countError func(errToken string)

	// lastHeaderStream is non-zero if the last frame was an
	// unfinished HEADERS/CONTINUATION.
	lastHeaderStream uint32

	maxReadSize uint32
	headerBuf   [http2frameHeaderLen]byte

	// TODO: let getReadBuf be configurable, and use a less memory-pinning
	// allocator in server.go to minimize memory pinned for many idle conns.
	// Will probably also need to make frame invalidation have a hook too.
	getReadBuf func(size uint32) []byte
	readBuf    []byte // cache for default getReadBuf

	w    io.Writer
	wbuf []byte

	// AllowIllegalReads permits the Framer's ReadFrame method
	// to return non-compliant frames or frame orders.
	// This is for testing and permits using the Framer to test
	// other HTTP/2 implementations' conformance to the spec.
	// It is not compatible with ReadMetaHeaders.
	AllowIllegalReads bool

	// ReadMetaHeaders if non-nil causes ReadFrame to merge
	// HEADERS and CONTINUATION frames together and return
	// MetaHeadersFrame instead.
	ReadMetaHeaders *hpack.Decoder

	// MaxHeaderListSize is the http2 MAX_HEADER_LIST_SIZE.
	// It's used only if ReadMetaHeaders is set; 0 means a sane default
	// (currently 16MB)
	// If the limit is hit, MetaHeadersFrame.Truncated is set true.
	MaxHeaderListSize uint32

	// TODO: track which type of frame & with which flags was sent
	// last. Then return an error (unless AllowIllegalWrites) if
	// we're in the middle of a header block and a
	// non-Continuation or Continuation on a different stream is
	// attempted to be written.

	logReads, logWrites bool

	debugFramer    *http2Framer // only use for logging written writes
	debugFramerBuf *bytes.Buffer

	frameCache *http2frameCache // nil if frames aren't reused (default)
}

const maxHeaderListSize = 16 << 20

func (fr *http2Framer) maxHeaderListSize() uint32 {
	if fr.MaxHeaderListSize == 0 {
		return 16 << 20 // sane default, per docs
	}
	return fr.MaxHeaderListSize
}

func (f *http2Framer) startWrite(ftype http2FrameType, flags http2Flags, streamID uint32) {
	// Write the FrameHeader.
	f.wbuf = append(f.wbuf[:0],
		0, // 3 bytes of length, filled in in endWrite
		0,
		0,
		byte(ftype),
		byte(flags),
		byte(streamID>>24),
		byte(streamID>>16),
		byte(streamID>>8),
		byte(streamID))
}

func (f *http2Framer) endWrite() error {
	// Now that we know the final size, fill in the FrameHeader in
	// the space previously reserved for it. Abuse append.
	length := len(f.wbuf) - http2frameHeaderLen
	if length >= (1 << 24) {
		return errHttp2FrameTooLarge
	}
	_ = append(f.wbuf[:0],
		byte(length>>16),
		byte(length>>8),
		byte(length))
	if f.logWrites {
		f.logWrite()
	}

	n, err := f.w.Write(f.wbuf)
	if err == nil && n != len(f.wbuf) {
		err = io.ErrShortWrite
	}
	return err
}

func (f *http2Framer) logWrite() {
	if f.debugFramer == nil {
		f.debugFramerBuf = new(bytes.Buffer)
		f.debugFramer = http2NewFramer(nil, f.debugFramerBuf)
		f.debugFramer.logReads = false // we log it ourselves, saying "wrote" below
		// Let us read anything, even if we accidentally wrote it
		// in the wrong order:
		f.debugFramer.AllowIllegalReads = true
	}
	f.debugFramerBuf.Write(f.wbuf)
	_, err := f.debugFramer.ReadFrame()
	if err != nil {
		return
	}
}

func (f *http2Framer) writeByte(v byte) { f.wbuf = append(f.wbuf, v) }

func (f *http2Framer) writeBytes(v []byte) { f.wbuf = append(f.wbuf, v...) }

func (f *http2Framer) writeUint16(v uint16) { f.wbuf = append(f.wbuf, byte(v>>8), byte(v)) }

func (f *http2Framer) writeUint32(v uint32) {
	f.wbuf = append(f.wbuf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

const (
	http2minMaxFrameSize = 1 << 14
	http2maxFrameSize    = 1<<24 - 1
)

// SetReuseFrames allows the Framer to reuse Frames.
// If called on a Framer, Frames returned by calls to ReadFrame are only
// valid until the next call to ReadFrame.
func (fr *http2Framer) SetReuseFrames() {
	if fr.frameCache != nil {
		return
	}
	fr.frameCache = &http2frameCache{}
}

type http2frameCache struct {
	dataFrame http2DataFrame
}

func (fc *http2frameCache) getDataFrame() *http2DataFrame {
	if fc == nil {
		return &http2DataFrame{}
	}
	return &fc.dataFrame
}

// NewFramer returns a Framer that writes frames to w and reads them from r.
func http2NewFramer(w io.Writer, r io.Reader) *http2Framer {
	fr := &http2Framer{
		w:          w,
		r:          r,
		countError: func(string) {},
	}
	fr.getReadBuf = func(size uint32) []byte {
		if cap(fr.readBuf) >= int(size) {
			return fr.readBuf[:size]
		}
		fr.readBuf = make([]byte, size)
		return fr.readBuf
	}
	fr.SetMaxReadFrameSize(http2maxFrameSize)
	return fr
}

// SetMaxReadFrameSize sets the maximum size of a frame
// that will be read by a subsequent call to ReadFrame.
// It is the caller's responsibility to advertise this
// limit with a SETTINGS frame.
func (fr *http2Framer) SetMaxReadFrameSize(v uint32) {
	if v > http2maxFrameSize {
		v = http2maxFrameSize
	}
	fr.maxReadSize = v
}

// ErrorDetail returns a more detailed error of the last error
// returned by Framer.ReadFrame. For instance, if ReadFrame
// returns a StreamError with code PROTOCOL_ERROR, ErrorDetail
// will say exactly what was invalid. ErrorDetail is not guaranteed
// to return a non-nil value and like the rest of the http2 package,
// its return value is not protected by an API compatibility promise.
// ErrorDetail is reset after the next call to ReadFrame.
func (fr *http2Framer) ErrorDetail() error {
	return fr.errDetail
}

// ErrFrameTooLarge is returned from Framer.ReadFrame when the peer
// sends a frame that is larger than declared with SetMaxReadFrameSize.
var errHttp2FrameTooLarge = errors.New("http2: frame too large")

// ReadFrame reads a single frame. The returned Frame is only valid
// until the next call to ReadFrame.
//
// If the frame is larger than previously set with SetMaxReadFrameSize, the
// returned error is ErrFrameTooLarge. Other errors may be of type
// ConnectionError, StreamError, or anything else from the underlying
// reader.
//
// If ReadFrame returns an error and a non-nil Frame, the Frame's StreamID
// indicates the stream responsible for the error.
func (fr *http2Framer) ReadFrame() (http2Frame, error) {
	fr.errDetail = nil
	if fr.lastFrame != nil {
		fr.lastFrame.invalidate()
	}
	fh, err := http2readFrameHeader(fr.headerBuf[:], fr.r)
	if err != nil {
		return nil, err
	}
	if fh.Length > fr.maxReadSize {
		return nil, errHttp2FrameTooLarge
	}
	payload := fr.getReadBuf(fh.Length)
	if _, err := io.ReadFull(fr.r, payload); err != nil {
		return nil, err
	}
	f, err := http2typeFrameParser(fh.Type)(fr.frameCache, fh, fr.countError, payload)
	if err != nil {
		return nil, err
	}
	if err := fr.checkFrameOrder(f); err != nil {
		return nil, err
	}
	if fh.Type == http2FrameHeaders && fr.ReadMetaHeaders != nil {
		return fr.readMetaFrame(f.(*http2HeadersFrame))
	}
	return f, nil
}

// connError returns ConnectionError(code) but first
// stashes away a public reason to the caller can optionally relay it
// to the peer before hanging up on them. This might help others debug
// their implementations.
func (fr *http2Framer) connError(code errHttp2Code, reason string) error {
	fr.errDetail = errors.New(reason)
	return http2ConnectionError(code)
}

// checkFrameOrder reports an error if f is an invalid frame to return
// next from ReadFrame. Mostly it checks whether HEADERS and
// CONTINUATION frames are contiguous.
func (fr *http2Framer) checkFrameOrder(f http2Frame) error {
	last := fr.lastFrame
	fr.lastFrame = f
	if fr.AllowIllegalReads {
		return nil
	}

	fh := f.Header()
	if fr.lastHeaderStream != 0 {
		if fh.Type != http2FrameContinuation {
			return fr.connError(errHttp2CodeProtocol,
				fmt.Sprintf("got %s for stream %d; expected CONTINUATION following %s for stream %d",
					fh.Type, fh.StreamID,
					last.Header().Type, fr.lastHeaderStream))
		}
		if fh.StreamID != fr.lastHeaderStream {
			return fr.connError(errHttp2CodeProtocol,
				fmt.Sprintf("got CONTINUATION for stream %d; expected stream %d",
					fh.StreamID, fr.lastHeaderStream))
		}
	} else if fh.Type == http2FrameContinuation {
		return fr.connError(errHttp2CodeProtocol, fmt.Sprintf("unexpected CONTINUATION for stream %d", fh.StreamID))
	}

	switch fh.Type {
	case http2FrameHeaders, http2FrameContinuation:
		if fh.Flags.Has(http2FlagHeadersEndHeaders) {
			fr.lastHeaderStream = 0
		} else {
			fr.lastHeaderStream = fh.StreamID
		}
	}

	return nil
}

// A DataFrame conveys arbitrary, variable-length sequences of octets
// associated with a stream.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.1
type http2DataFrame struct {
	http2FrameHeader
	data []byte
}

func (f *http2DataFrame) StreamEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagDataEndStream)
}

// Data returns the frame's data octets, not including any padding
// size byte or padding suffix bytes.
// The caller must not retain the returned memory past the next
// call to ReadFrame.
func (f *http2DataFrame) Data() []byte {
	f.checkValid()
	return f.data
}

func http2parseDataFrame(fc *http2frameCache, fh http2FrameHeader, countError func(string), payload []byte) (http2Frame, error) {
	if fh.StreamID == 0 {
		// DATA frames MUST be associated with a stream. If a
		// DATA frame is received whose stream identifier
		// field is 0x0, the recipient MUST respond with a
		// connection error (Section 5.4.1) of type
		// PROTOCOL_ERROR.
		countError("frame_data_stream_0")
		return nil, errors.New("DATA frame with stream ID 0")
	}
	f := fc.getDataFrame()
	f.http2FrameHeader = fh

	var padSize byte
	if fh.Flags.Has(http2FlagDataPadded) {
		var err error
		payload, padSize, err = http2readByte(payload)
		if err != nil {
			countError("frame_data_pad_byte_short")
			return nil, err
		}
	}
	if int(padSize) > len(payload) {
		// If the length of the padding is greater than the
		// length of the frame payload, the recipient MUST
		// treat this as a connection error.
		// Filed: https://github.com/http2/http2-spec/issues/610
		countError("frame_data_pad_too_big")
		return nil, errors.New("pad size larger than data payload")
	}
	f.data = payload[:len(payload)-int(padSize)]
	return f, nil
}

var (
	errHttp2PadLength = errors.New("pad length too large")
)

// WriteData writes a DATA frame.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility not to violate the maximum frame size
// and to not call other Write methods concurrently.
func (f *http2Framer) WriteData(streamID uint32, endStream bool, data []byte) error {
	return f.WriteDataPadded(streamID, endStream, data, nil)
}

// WriteDataPadded writes a DATA frame with optional padding.
//
// If pad is nil, the padding bit is not sent.
// The length of pad must not exceed 255 bytes.
// The bytes of pad must all be zero, unless f.AllowIllegalWrites is set.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility not to violate the maximum frame size
// and to not call other Write methods concurrently.
func (f *http2Framer) WriteDataPadded(streamID uint32, endStream bool, data, pad []byte) error {
	if err := f.startWriteDataPadded(streamID, endStream, data, pad); err != nil {
		return err
	}
	return f.endWrite()
}

// startWriteDataPadded is WriteDataPadded, but only writes the frame to the Framer's internal buffer.
// The caller should call endWrite to flush the frame to the underlying writer.
func (f *http2Framer) startWriteDataPadded(streamID uint32, endStream bool, data, pad []byte) error {
	if len(pad) > 255 {
		return errHttp2PadLength
	}
	var flags http2Flags
	if endStream {
		flags |= http2FlagDataEndStream
	}
	if pad != nil {
		flags |= http2FlagDataPadded
	}
	f.startWrite(http2FrameData, flags, streamID)
	if pad != nil {
		f.wbuf = append(f.wbuf, byte(len(pad)))
	}
	f.wbuf = append(f.wbuf, data...)
	f.wbuf = append(f.wbuf, pad...)
	return nil
}

// A SettingsFrame conveys configuration parameters that affect how
// endpoints communicate, such as preferences and constraints on peer
// behavior.
//
// See https://httpwg.org/specs/rfc7540.html#SETTINGS
type http2SettingsFrame struct {
	http2FrameHeader
	p []byte
}

func http2parseSettingsFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	if fh.Flags.Has(http2FlagSettingsAck) && fh.Length > 0 {
		// When this (ACK 0x1) bit is set, the payload of the
		// SETTINGS frame MUST be empty. Receipt of a
		// SETTINGS frame with the ACK flag set and a length
		// field value other than 0 MUST be treated as a
		// connection error (Section 5.4.1) of type
		// FRAME_SIZE_ERROR.
		countError("frame_settings_ack_with_length")
		return nil, http2ConnectionError(errHttp2CodeFrameSize)
	}
	if fh.StreamID != 0 {
		// SETTINGS frames always apply to a connection,
		// never a single stream. The stream identifier for a
		// SETTINGS frame MUST be zero (0x0).  If an endpoint
		// receives a SETTINGS frame whose stream identifier
		// field is anything other than 0x0, the endpoint MUST
		// respond with a connection error (Section 5.4.1) of
		// type PROTOCOL_ERROR.
		countError("frame_settings_has_stream")
		return nil, http2ConnectionError(errHttp2CodeProtocol)
	}
	if len(p)%6 != 0 {
		countError("frame_settings_mod_6")
		// Expecting even number of 6 byte settings.
		return nil, http2ConnectionError(errHttp2CodeFrameSize)
	}
	f := &http2SettingsFrame{http2FrameHeader: fh, p: p}
	if v, ok := f.Value(http2SettingInitialWindowSize); ok && v > (1<<31)-1 {
		countError("frame_settings_window_size_too_big")
		// Values above the maximum flow control window size of 2^31 - 1 MUST
		// be treated as a connection error (Section 5.4.1) of type
		// FLOW_CONTROL_ERROR.
		return nil, http2ConnectionError(errHttp2CodeFlowControl)
	}
	return f, nil
}

func (f *http2SettingsFrame) IsAck() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagSettingsAck)
}

func (f *http2SettingsFrame) Value(id http2SettingID) (v uint32, ok bool) {
	f.checkValid()
	for i := 0; i < f.NumSettings(); i++ {
		if s := f.Setting(i); s.ID == id {
			return s.Val, true
		}
	}
	return 0, false
}

// Setting returns the setting from the frame at the given 0-based index.
// The index must be >= 0 and less than f.NumSettings().
func (f *http2SettingsFrame) Setting(i int) http2Setting {
	buf := f.p
	return http2Setting{
		ID:  http2SettingID(binary.BigEndian.Uint16(buf[i*6 : i*6+2])),
		Val: binary.BigEndian.Uint32(buf[i*6+2 : i*6+6]),
	}
}

func (f *http2SettingsFrame) NumSettings() int { return len(f.p) / 6 }

// HasDuplicates reports whether f contains any duplicate setting IDs.
func (f *http2SettingsFrame) HasDuplicates() bool {
	num := f.NumSettings()
	if num == 0 {
		return false
	}
	// If it's small enough (the common case), just do the n^2
	// thing and avoid a map allocation.
	if num < 10 {
		for i := 0; i < num; i++ {
			idi := f.Setting(i).ID
			for j := i + 1; j < num; j++ {
				idj := f.Setting(j).ID
				if idi == idj {
					return true
				}
			}
		}
		return false
	}
	seen := map[http2SettingID]bool{}
	for i := 0; i < num; i++ {
		id := f.Setting(i).ID
		if seen[id] {
			return true
		}
		seen[id] = true
	}
	return false
}

// ForeachSetting runs fn for each setting.
// It stops and returns the first error.
func (f *http2SettingsFrame) ForeachSetting(fn func(http2Setting) error) error {
	f.checkValid()
	for i := 0; i < f.NumSettings(); i++ {
		if err := fn(f.Setting(i)); err != nil {
			return err
		}
	}
	return nil
}

// WriteSettings writes a SETTINGS frame with zero or more settings
// specified and the ACK bit not set.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WriteSettings(settings ...http2Setting) error {
	f.startWrite(http2FrameSettings, 0, 0)
	for _, s := range settings {
		f.writeUint16(uint16(s.ID))
		f.writeUint32(s.Val)
	}
	return f.endWrite()
}

// WriteSettingsAck writes an empty SETTINGS frame with the ACK bit set.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WriteSettingsAck() error {
	f.startWrite(http2FrameSettings, http2FlagSettingsAck, 0)
	return f.endWrite()
}

// A PingFrame is a mechanism for measuring a minimal round trip time
// from the sender, as well as determining whether an idle connection
// is still functional.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.7
type http2PingFrame struct {
	http2FrameHeader
	Data [8]byte
}

func (f *http2PingFrame) IsAck() bool { return f.Flags.Has(http2FlagPingAck) }

func http2parsePingFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), payload []byte) (http2Frame, error) {
	if len(payload) != 8 {
		countError("frame_ping_length")
		return nil, http2ConnectionError(errHttp2CodeFrameSize)
	}
	if fh.StreamID != 0 {
		countError("frame_ping_has_stream")
		return nil, http2ConnectionError(errHttp2CodeProtocol)
	}
	f := &http2PingFrame{http2FrameHeader: fh}
	copy(f.Data[:], payload)
	return f, nil
}

func (f *http2Framer) WritePing(ack bool, data [8]byte) error {
	var flags http2Flags
	if ack {
		flags = http2FlagPingAck
	}
	f.startWrite(http2FramePing, flags, 0)
	f.writeBytes(data[:])
	return f.endWrite()
}

// A GoAwayFrame informs the remote peer to stop creating streams on this connection.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.8
type http2GoAwayFrame struct {
	http2FrameHeader
	LastStreamID uint32
	ErrCode      errHttp2Code
	debugData    []byte
}

// DebugData returns any debug data in the GOAWAY frame. Its contents
// are not defined.
// The caller must not retain the returned memory past the next
// call to ReadFrame.
func (f *http2GoAwayFrame) DebugData() []byte {
	f.checkValid()
	return f.debugData
}

func http2parseGoAwayFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	if fh.StreamID != 0 {
		countError("frame_goaway_has_stream")
		return nil, http2ConnectionError(errHttp2CodeProtocol)
	}
	if len(p) < 8 {
		countError("frame_goaway_short")
		return nil, http2ConnectionError(errHttp2CodeFrameSize)
	}
	return &http2GoAwayFrame{
		http2FrameHeader: fh,
		LastStreamID:     binary.BigEndian.Uint32(p[:4]) & (1<<31 - 1),
		ErrCode:          errHttp2Code(binary.BigEndian.Uint32(p[4:8])),
		debugData:        p[8:],
	}, nil
}

func (f *http2Framer) WriteGoAway(maxStreamID uint32, code errHttp2Code, debugData []byte) error {
	f.startWrite(http2FrameGoAway, 0, 0)
	f.writeUint32(maxStreamID & (1<<31 - 1))
	f.writeUint32(uint32(code))
	f.writeBytes(debugData)
	return f.endWrite()
}

// An UnknownFrame is the frame type returned when the frame type is unknown
// or no specific frame type parser exists.
type http2UnknownFrame struct {
	http2FrameHeader
	p []byte
}

// Payload returns the frame's payload (after the header).  It is not
// valid to call this method after a subsequent call to
// Framer.ReadFrame, nor is it valid to retain the returned slice.
// The memory is owned by the Framer and is invalidated when the next
// frame is read.
func (f *http2UnknownFrame) Payload() []byte {
	f.checkValid()
	return f.p
}

func http2parseUnknownFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	return &http2UnknownFrame{fh, p}, nil
}

// A WindowUpdateFrame is used to implement flow control.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.9
type http2WindowUpdateFrame struct {
	http2FrameHeader
	Increment uint32 // never read with high bit set
}

func http2parseWindowUpdateFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	if len(p) != 4 {
		countError("frame_windowupdate_bad_len")
		return nil, http2ConnectionError(errHttp2CodeFrameSize)
	}
	inc := binary.BigEndian.Uint32(p[:4]) & 0x7fffffff // mask off high reserved bit
	if inc == 0 {
		// A receiver MUST treat the receipt of a
		// WINDOW_UPDATE frame with an flow control window
		// increment of 0 as a stream error (Section 5.4.2) of
		// type PROTOCOL_ERROR; errors on the connection flow
		// control window MUST be treated as a connection
		// error (Section 5.4.1).
		if fh.StreamID == 0 {
			countError("frame_windowupdate_zero_inc_conn")
			return nil, http2ConnectionError(errHttp2CodeProtocol)
		}
		countError("frame_windowupdate_zero_inc_stream")
		return nil, fmt.Errorf("empty flow control window increment: %v", errHttp2CodeProtocol)
	}
	return &http2WindowUpdateFrame{
		http2FrameHeader: fh,
		Increment:        inc,
	}, nil
}

// WriteWindowUpdate writes a WINDOW_UPDATE frame.
// The increment value must be between 1 and 2,147,483,647, inclusive.
// If the Stream ID is zero, the window update applies to the
// connection as a whole.
func (f *http2Framer) WriteWindowUpdate(streamID, incr uint32) error {
	f.startWrite(http2FrameWindowUpdate, 0, streamID)
	f.writeUint32(incr)
	return f.endWrite()
}

// A HeadersFrame is used to open a stream and additionally carries a
// header block fragment.
type http2HeadersFrame struct {
	http2FrameHeader

	// Priority is set if FlagHeadersPriority is set in the FrameHeader.
	Priority http2PriorityParam

	headerFragBuf []byte // not owned
}

func (f *http2HeadersFrame) HeaderBlockFragment() []byte {
	f.checkValid()
	return f.headerFragBuf
}

func (f *http2HeadersFrame) HeadersEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagHeadersEndHeaders)
}

func (f *http2HeadersFrame) StreamEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagHeadersEndStream)
}

func (f *http2HeadersFrame) HasPriority() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagHeadersPriority)
}

// HeadersFrameParam are the parameters for writing a HEADERS frame.
type http2HeadersFrameParam struct {
	// StreamID is the required Stream ID to initiate.
	StreamID uint32
	// BlockFragment is part (or all) of a Header Block.
	BlockFragment []byte

	// EndStream indicates that the header block is the last that
	// the endpoint will send for the identified stream. Setting
	// this flag causes the stream to enter one of "half closed"
	// states.
	EndStream bool

	// EndHeaders indicates that this frame contains an entire
	// header block and is not followed by any
	// CONTINUATION frames.
	EndHeaders bool

	// PadLength is the optional number of bytes of zeros to add
	// to this frame.
	PadLength uint8

	// Priority, if non-zero, includes stream priority information
	// in the HEADER frame.
	Priority http2PriorityParam
}

// WriteHeaders writes a single HEADERS frame.
//
// This is a low-level header writing method. Encoding headers and
// splitting them into any necessary CONTINUATION frames is handled
// elsewhere.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WriteHeaders(p http2HeadersFrameParam) error {
	var flags http2Flags
	if p.PadLength != 0 {
		flags |= http2FlagHeadersPadded
	}
	if p.EndStream {
		flags |= http2FlagHeadersEndStream
	}
	if p.EndHeaders {
		flags |= http2FlagHeadersEndHeaders
	}
	if !p.Priority.IsZero() {
		flags |= http2FlagHeadersPriority
	}
	f.startWrite(http2FrameHeaders, flags, p.StreamID)
	if p.PadLength != 0 {
		f.writeByte(p.PadLength)
	}
	if !p.Priority.IsZero() {
		v := p.Priority.StreamDep
		if p.Priority.Exclusive {
			v |= 1 << 31
		}
		f.writeUint32(v)
		f.writeByte(p.Priority.Weight)
	}
	f.wbuf = append(f.wbuf, p.BlockFragment...)
	f.wbuf = append(f.wbuf, http2padZeros[:p.PadLength]...)
	return f.endWrite()
}

// A PriorityFrame specifies the sender-advised priority of a stream.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.3
type http2PriorityFrame struct {
	http2FrameHeader
	http2PriorityParam
}

// PriorityParam are the stream prioritzation parameters.
type http2PriorityParam struct {
	// StreamDep is a 31-bit stream identifier for the
	// stream that this stream depends on. Zero means no
	// dependency.
	StreamDep uint32

	// Exclusive is whether the dependency is exclusive.
	Exclusive bool

	// Weight is the stream's zero-indexed weight. It should be
	// set together with StreamDep, or neither should be set. Per
	// the spec, "Add one to the value to obtain a weight between
	// 1 and 256."
	Weight uint8
}

func (p http2PriorityParam) IsZero() bool {
	return p == http2PriorityParam{}
}

func http2parsePriorityFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), payload []byte) (http2Frame, error) {
	if fh.StreamID == 0 {
		countError("frame_priority_zero_stream")
		return nil, errors.New("PRIORITY frame with stream ID 0")
	}
	if len(payload) != 5 {
		countError("frame_priority_bad_length")
		return nil, fmt.Errorf("PRIORITY frame payload size was %d; want 5", len(payload))
	}
	v := binary.BigEndian.Uint32(payload[:4])
	streamID := v & 0x7fffffff // mask off high bit
	return &http2PriorityFrame{
		http2FrameHeader: fh,
		http2PriorityParam: http2PriorityParam{
			Weight:    payload[4],
			StreamDep: streamID,
			Exclusive: streamID != v, // was high bit set?
		},
	}, nil
}

// WritePriority writes a PRIORITY frame.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WritePriority(streamID uint32, p http2PriorityParam) error {
	f.startWrite(http2FramePriority, 0, streamID)
	v := p.StreamDep
	if p.Exclusive {
		v |= 1 << 31
	}
	f.writeUint32(v)
	f.writeByte(p.Weight)
	return f.endWrite()
}

// A RSTStreamFrame allows for abnormal termination of a stream.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.4
type http2RSTStreamFrame struct {
	http2FrameHeader
	ErrCode errHttp2Code
}

func http2parseRSTStreamFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	if len(p) != 4 {
		countError("frame_rststream_bad_len")
		return nil, http2ConnectionError(errHttp2CodeFrameSize)
	}
	if fh.StreamID == 0 {
		countError("frame_rststream_zero_stream")
		return nil, http2ConnectionError(errHttp2CodeProtocol)
	}
	return &http2RSTStreamFrame{fh, errHttp2Code(binary.BigEndian.Uint32(p[:4]))}, nil
}

// WriteRSTStream writes a RST_STREAM frame.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WriteRSTStream(streamID uint32, code errHttp2Code) error {
	f.startWrite(http2FrameRSTStream, 0, streamID)
	f.writeUint32(uint32(code))
	return f.endWrite()
}

// A ContinuationFrame is used to continue a sequence of header block fragments.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.10
type http2ContinuationFrame struct {
	http2FrameHeader
	headerFragBuf []byte
}

func http2parseContinuationFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	if fh.StreamID == 0 {
		countError("frame_continuation_zero_stream")
		return nil, errors.New("CONTINUATION frame with stream ID 0")
	}
	return &http2ContinuationFrame{fh, p}, nil
}

func (f *http2ContinuationFrame) HeaderBlockFragment() []byte {
	f.checkValid()
	return f.headerFragBuf
}

func (f *http2ContinuationFrame) HeadersEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagContinuationEndHeaders)
}

// WriteContinuation writes a CONTINUATION frame.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WriteContinuation(streamID uint32, endHeaders bool, headerBlockFragment []byte) error {
	var flags http2Flags
	if endHeaders {
		flags |= http2FlagContinuationEndHeaders
	}
	f.startWrite(http2FrameContinuation, flags, streamID)
	f.wbuf = append(f.wbuf, headerBlockFragment...)
	return f.endWrite()
}

// A PushPromiseFrame is used to initiate a server stream.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.6
type http2PushPromiseFrame struct {
	http2FrameHeader
	PromiseID     uint32
	headerFragBuf []byte // not owned
}

func (f *http2PushPromiseFrame) HeaderBlockFragment() []byte {
	f.checkValid()
	return f.headerFragBuf
}

func (f *http2PushPromiseFrame) HeadersEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagPushPromiseEndHeaders)
}

func http2parsePushPromise(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (_ http2Frame, err error) {
	pp := &http2PushPromiseFrame{
		http2FrameHeader: fh,
	}
	if pp.StreamID == 0 {
		// PUSH_PROMISE frames MUST be associated with an existing,
		// peer-initiated stream. The stream identifier of a
		// PUSH_PROMISE frame indicates the stream it is associated
		// with. If the stream identifier field specifies the value
		// 0x0, a recipient MUST respond with a connection error
		// (Section 5.4.1) of type PROTOCOL_ERROR.
		countError("frame_pushpromise_zero_stream")
		return nil, http2ConnectionError(errHttp2CodeProtocol)
	}
	// The PUSH_PROMISE frame includes optional padding.
	// Padding fields and flags are identical to those defined for DATA frames
	var padLength uint8
	if fh.Flags.Has(http2FlagPushPromisePadded) {
		if p, padLength, err = http2readByte(p); err != nil {
			countError("frame_pushpromise_pad_short")
			return
		}
	}

	p, pp.PromiseID, err = http2readUint32(p)
	if err != nil {
		countError("frame_pushpromise_promiseid_short")
		return
	}
	pp.PromiseID = pp.PromiseID & (1<<31 - 1)

	if int(padLength) > len(p) {
		// like the DATA frame, error out if padding is longer than the body.
		countError("frame_pushpromise_pad_too_big")
		return nil, http2ConnectionError(errHttp2CodeProtocol)
	}
	pp.headerFragBuf = p[:len(p)-int(padLength)]
	return pp, nil
}

// PushPromiseParam are the parameters for writing a PUSH_PROMISE frame.
type http2PushPromiseParam struct {
	// StreamID is the required Stream ID to initiate.
	StreamID uint32

	// PromiseID is the required Stream ID which this
	// Push Promises
	PromiseID uint32

	// BlockFragment is part (or all) of a Header Block.
	BlockFragment []byte

	// EndHeaders indicates that this frame contains an entire
	// header block and is not followed by any
	// CONTINUATION frames.
	EndHeaders bool

	// PadLength is the optional number of bytes of zeros to add
	// to this frame.
	PadLength uint8
}

// WritePushPromise writes a single PushPromise Frame.
//
// As with Header Frames, This is the low level call for writing
// individual frames. Continuation frames are handled elsewhere.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WritePushPromise(p http2PushPromiseParam) error {
	var flags http2Flags
	if p.PadLength != 0 {
		flags |= http2FlagPushPromisePadded
	}
	if p.EndHeaders {
		flags |= http2FlagPushPromiseEndHeaders
	}
	f.startWrite(http2FramePushPromise, flags, p.StreamID)
	if p.PadLength != 0 {
		f.writeByte(p.PadLength)
	}
	f.writeUint32(p.PromiseID)
	f.wbuf = append(f.wbuf, p.BlockFragment...)
	f.wbuf = append(f.wbuf, http2padZeros[:p.PadLength]...)
	return f.endWrite()
}

// WriteRawFrame writes a raw frame. This can be used to write
// extension frames unknown to this package.
func (f *http2Framer) WriteRawFrame(t http2FrameType, flags http2Flags, streamID uint32, payload []byte) error {
	f.startWrite(t, flags, streamID)
	f.writeBytes(payload)
	return f.endWrite()
}

func http2readByte(p []byte) (remain []byte, b byte, err error) {
	if len(p) == 0 {
		return nil, 0, io.ErrUnexpectedEOF
	}
	return p[1:], p[0], nil
}

func http2readUint32(p []byte) (remain []byte, v uint32, err error) {
	if len(p) < 4 {
		return nil, 0, io.ErrUnexpectedEOF
	}
	return p[4:], binary.BigEndian.Uint32(p[:4]), nil
}

type http2headersEnder interface {
	HeadersEnded() bool
}

type http2headersOrContinuation interface {
	http2headersEnder
	HeaderBlockFragment() []byte
}

// A MetaHeadersFrame is the representation of one HEADERS frame and
// zero or more contiguous CONTINUATION frames and the decoding of
// their HPACK-encoded contents.
//
// This type of frame does not appear on the wire and is only returned
// by the Framer when Framer.ReadMetaHeaders is set.
type http2MetaHeadersFrame struct {
	*http2HeadersFrame

	// Fields are the fields contained in the HEADERS and
	// CONTINUATION frames. The underlying slice is owned by the
	// Framer and must not be retained after the next call to
	// ReadFrame.
	//
	// Fields are guaranteed to be in the correct http2 order and
	// not have unknown pseudo header fields or invalid header
	// field names or values. Required pseudo header fields may be
	// missing, however. Use the MetaHeadersFrame.Pseudo accessor
	// method access pseudo headers.
	Fields []hpack.HeaderField

	// Truncated is whether the max header list size limit was hit
	// and Fields is incomplete. The hpack decoder state is still
	// valid, however.
	Truncated bool
}

// PseudoValue returns the given pseudo header field's value.
// The provided pseudo field should not contain the leading colon.
func (mh *http2MetaHeadersFrame) PseudoValue(pseudo string) string {
	for _, hf := range mh.Fields {
		if !hf.IsPseudo() {
			return ""
		}
		if hf.Name[1:] == pseudo {
			return hf.Value
		}
	}
	return ""
}

// RegularFields returns the regular (non-pseudo) header fields of mh.
// The caller does not own the returned slice.
func (mh *http2MetaHeadersFrame) RegularFields() []hpack.HeaderField {
	for i, hf := range mh.Fields {
		if !hf.IsPseudo() {
			return mh.Fields[i:]
		}
	}
	return nil
}

// PseudoFields returns the pseudo header fields of mh.
// The caller does not own the returned slice.
func (mh *http2MetaHeadersFrame) PseudoFields() []hpack.HeaderField {
	for i, hf := range mh.Fields {
		if !hf.IsPseudo() {
			return mh.Fields[:i]
		}
	}
	return mh.Fields
}

// readMetaFrame returns 0 or more CONTINUATION frames from fr and
// merge them into the provided hf and returns a MetaHeadersFrame
// with the decoded hpack values.
func (fr *http2Framer) readMetaFrame(hf *http2HeadersFrame) (http2Frame, error) {
	if fr.AllowIllegalReads {
		return nil, errors.New("illegal use of AllowIllegalReads with ReadMetaHeaders")
	}

	mh := &http2MetaHeadersFrame{
		http2HeadersFrame: hf,
	}
	var remainSize = fr.maxHeaderListSize()
	var sawRegular bool
	var invalid error // pseudo header field errors
	hdec := fr.ReadMetaHeaders
	hdec.SetEmitEnabled(true)
	hdec.SetEmitFunc(func(hf hpack.HeaderField) {
		if !httpguts.ValidHeaderFieldValue(hf.Value) {
			// Don't include the value in the error, because it may be sensitive.
			invalid = fmt.Errorf("ValidHeaderFieldValue: %s", hf.Name)
		}
		isPseudo := strings.HasPrefix(hf.Name, ":")
		if isPseudo {
			if sawRegular {
				invalid = errHttp2PseudoAfterRegular
			}
		} else {
			sawRegular = true
			if !http2validWireHeaderFieldName(hf.Name) {
				invalid = fmt.Errorf("ValidHeaderFieldValue: %s", hf.Name)
			}
		}

		if invalid != nil {
			hdec.SetEmitEnabled(false)
			return
		}

		size := hf.Size()
		if size > remainSize {
			hdec.SetEmitEnabled(false)
			mh.Truncated = true
			remainSize = 0
			return
		}
		remainSize -= size

		mh.Fields = append(mh.Fields, hf)
	})
	// Lose reference to MetaHeadersFrame:
	defer hdec.SetEmitFunc(func(hf hpack.HeaderField) {})

	var hc http2headersOrContinuation = hf
	for {
		frag := hc.HeaderBlockFragment()

		// Avoid parsing large amounts of headers that we will then discard.
		// If the sender exceeds the max header list size by too much,
		// skip parsing the fragment and close the connection.
		//
		// "Too much" is either any CONTINUATION frame after we've already
		// exceeded the max header list size (in which case remainSize is 0),
		// or a frame whose encoded size is more than twice the remaining
		// header list bytes we're willing to accept.
		if int64(len(frag)) > int64(2*remainSize) {
			// It would be nice to send a RST_STREAM before sending the GOAWAY,
			// but the structure of the server's frame writer makes this difficult.
			return mh, http2ConnectionError(errHttp2CodeProtocol)
		}
		// Also close the connection after any CONTINUATION frame following an
		// invalid header, since we stop tracking the size of the headers after
		// an invalid one.
		if invalid != nil {
			// It would be nice to send a RST_STREAM before sending the GOAWAY,
			// but the structure of the server's frame writer makes this difficult.
			return mh, http2ConnectionError(errHttp2CodeProtocol)
		}
		if _, err := hdec.Write(frag); err != nil {
			return mh, http2ConnectionError(errHttp2CodeCompression)
		}

		if hc.HeadersEnded() {
			break
		}
		if f, err := fr.ReadFrame(); err != nil {
			return nil, err
		} else {
			hc = f.(*http2ContinuationFrame) // guaranteed by checkFrameOrder
		}
	}

	mh.http2HeadersFrame.headerFragBuf = nil
	mh.http2HeadersFrame.invalidate()

	if err := hdec.Close(); err != nil {
		return mh, http2ConnectionError(errHttp2CodeCompression)
	}
	if invalid != nil {
		fr.errDetail = invalid
		return nil, invalid
	}
	return mh, nil
}

var (
	http2commonBuildOnce   sync.Once
	http2commonLowerHeader map[string]string // Go-Canonical-Case -> lower-case
	http2commonCanonHeader map[string]string // lower-case -> Go-Canonical-Case
)

func http2buildCommonHeaderMapsOnce() {
	http2commonBuildOnce.Do(http2buildCommonHeaderMaps)
}

func http2buildCommonHeaderMaps() {
	common := []string{
		"accept",
		"accept-charset",
		"accept-encoding",
		"accept-language",
		"accept-ranges",
		"age",
		"access-control-allow-credentials",
		"access-control-allow-headers",
		"access-control-allow-methods",
		"access-control-allow-origin",
		"access-control-expose-headers",
		"access-control-max-age",
		"access-control-request-headers",
		"access-control-request-method",
		"allow",
		"authorization",
		"cache-control",
		"content-disposition",
		"content-encoding",
		"content-language",
		"content-length",
		"content-location",
		"content-range",
		"content-type",
		"cookie",
		"date",
		"etag",
		"expect",
		"expires",
		"from",
		"host",
		"if-match",
		"if-modified-since",
		"if-none-match",
		"if-unmodified-since",
		"last-modified",
		"link",
		"location",
		"max-forwards",
		"origin",
		"proxy-authenticate",
		"proxy-authorization",
		"range",
		"referer",
		"refresh",
		"retry-after",
		"server",
		"set-cookie",
		"strict-transport-security",
		"trailer",
		"transfer-encoding",
		"user-agent",
		"vary",
		"via",
		"www-authenticate",
		"x-forwarded-for",
		"x-forwarded-proto",
	}
	http2commonLowerHeader = make(map[string]string, len(common))
	http2commonCanonHeader = make(map[string]string, len(common))
	for _, v := range common {
		chk := http.CanonicalHeaderKey(v)
		http2commonLowerHeader[chk] = v
		http2commonCanonHeader[v] = chk
	}
}

func http2lowerHeader(v string) (lower string, ascii bool) {
	http2buildCommonHeaderMapsOnce()
	if s, ok := http2commonLowerHeader[v]; ok {
		return s, true
	}
	return http2asciiToLower(v)
}

func http2canonicalHeader(v string) string {
	http2buildCommonHeaderMapsOnce()
	if s, ok := http2commonCanonHeader[v]; ok {
		return s
	}
	return http.CanonicalHeaderKey(v)
}

const (
	// ClientPreface is the string that must be sent by new
	// connections from clients.
	http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	// SETTINGS_MAX_FRAME_SIZE default
	// https://httpwg.org/specs/rfc7540.html#rfc.section.6.5.2

	// https://httpwg.org/specs/rfc7540.html#SettingValues
)

var (
	http2clientPreface = []byte(http2ClientPreface)
)

// Setting is a setting parameter: which setting it is, and its value.
type http2Setting struct {
	// ID is which setting is being set.
	// See https://httpwg.org/specs/rfc7540.html#SettingFormat
	ID http2SettingID

	// Val is the value.
	Val uint32
}

func (s http2Setting) String() string {
	return fmt.Sprintf("[%v = %d]", s.ID, s.Val)
}

// Valid reports whether the setting is valid.
func (s http2Setting) Valid() error {
	// Limits and error codes from 6.5.2 Defined SETTINGS Parameters
	switch s.ID {
	case http2SettingEnablePush:
		if s.Val != 1 && s.Val != 0 {
			return http2ConnectionError(errHttp2CodeProtocol)
		}
	case http2SettingInitialWindowSize:
		if s.Val > 1<<31-1 {
			return http2ConnectionError(errHttp2CodeFlowControl)
		}
	case http2SettingMaxFrameSize:
		if s.Val < 16384 || s.Val > 1<<24-1 {
			return http2ConnectionError(errHttp2CodeProtocol)
		}
	}
	return nil
}

// A SettingID is an HTTP/2 setting as defined in
// https://httpwg.org/specs/rfc7540.html#iana-settings
type http2SettingID uint16

const (
	http2SettingHeaderTableSize      http2SettingID = 0x1
	http2SettingEnablePush           http2SettingID = 0x2
	http2SettingMaxConcurrentStreams http2SettingID = 0x3
	http2SettingInitialWindowSize    http2SettingID = 0x4
	http2SettingMaxFrameSize         http2SettingID = 0x5
	http2SettingMaxHeaderListSize    http2SettingID = 0x6
)

var http2settingName = map[http2SettingID]string{
	http2SettingHeaderTableSize:      "HEADER_TABLE_SIZE",
	http2SettingEnablePush:           "ENABLE_PUSH",
	http2SettingMaxConcurrentStreams: "MAX_CONCURRENT_STREAMS",
	http2SettingInitialWindowSize:    "INITIAL_WINDOW_SIZE",
	http2SettingMaxFrameSize:         "MAX_FRAME_SIZE",
	http2SettingMaxHeaderListSize:    "MAX_HEADER_LIST_SIZE",
}

func (s http2SettingID) String() string {
	if v, ok := http2settingName[s]; ok {
		return v
	}
	return fmt.Sprintf("UNKNOWN_SETTING_%d", uint16(s))
}

// validWireHeaderFieldName reports whether v is a valid header field
// name (key). See httpguts.ValidHeaderName for the base rules.
//
// Further, http2 says:
//
//	"Just as in HTTP/1.x, header field names are strings of ASCII
//	characters that are compared in a case-insensitive
//	fashion. However, header field names MUST be converted to
//	lowercase prior to their encoding in HTTP/2. "
func http2validWireHeaderFieldName(v string) bool {
	if len(v) == 0 {
		return false
	}
	for _, r := range v {
		if !httpguts.IsTokenRune(r) {
			return false
		}
		if 'A' <= r && r <= 'Z' {
			return false
		}
	}
	return true
}

func http2mustUint31(v int32) uint32 {
	if v < 0 {
		panic("out of range")
	}
	return uint32(v)
}

// validPseudoPath reports whether v is a valid :path pseudo-header
// value. It must be either:
//
//   - a non-empty string starting with '/'
//   - the string '*', for OPTIONS requests.
//
// For now this is only used a quick check for deciding when to clean
// up Opaque URLs before sending requests from the Transport.
// See golang.org/issue/16847
//
// We used to enforce that the path also didn't start with "//", but
// Google's GFE accepts such paths and Chrome sends them, so ignore
// that part of the spec. See golang.org/issue/19103.
func http2validPseudoPath(v string) bool {
	return (len(v) > 0 && v[0] == '/') || v == "*"
}

// incomparable is a zero-width, non-comparable type. Adding it to a struct
// makes that struct also non-comparable, and generally doesn't add
// any size (as long as it's first).
type http2incomparable [0]func()

// stream represents a stream. This is the minimal metadata needed by
// the serve goroutine. Most of the actual stream state is owned by
// the http.Handler's goroutine in the responseWriter. Because the
// responseWriter's responseWriterState is recycled at the end of a
// handler, this struct intentionally has no pointer to the
// *responseWriter{,State} itself, as the Handler ending nils out the
// responseWriter's state field.

// foreachHeaderElement splits v according to the "#rule" construction
// in RFC 7230 section 7 and calls fn for each non-empty element.
func http2foreachHeaderElement(v string, fn func(string)) {
	v = textproto.TrimString(v)
	if v == "" {
		return
	}
	if !strings.Contains(v, ",") {
		fn(v)
		return
	}
	for _, f := range strings.Split(v, ",") {
		if f = textproto.TrimString(f); f != "" {
			fn(f)
		}
	}
}

// ClientConn is the state of a single HTTP/2 client connection to an
// HTTP/2 server.
type Http2ClientConn struct {
	closeFunc         func()
	spec              gospiderOption
	loop              *http2clientConnReadLoop
	http2clientStream *http2clientStream
	ctx               context.Context
	cnl               context.CancelFunc
	err               error
	tconn             net.Conn     // usually *tls.Conn, except specialized impls
	flow              http2outflow // our conn-level flow control quota (cs.outflow is per stream)
	inflow            http2inflow  // peer's conn-level flow control

	nextStreamID          uint32
	maxFrameSize          uint32
	peerMaxHeaderListSize uint64
	initialWindowSize     uint32

	bw *bufio.Writer
	fr *http2Framer

	hbuf bytes.Buffer // HPACK encoder writes into this
	henc *hpack.Encoder
}

type http2clientStream struct {
	cc                   *Http2ClientConn
	ctx                  context.Context
	headCtx              context.Context
	headCnl              context.CancelFunc
	resp                 *http.Response
	ID                   uint32
	bodyReader           *io.PipeReader
	bodyWriter           *io.PipeWriter
	flow                 http2outflow // guarded by cc.mu
	inflow               http2inflow  // guarded by cc.mu
	reqBody              io.ReadCloser
	reqBodyContentLength int64 // -1 means unknown
}

func (cc *Http2ClientConn) run() (err error) {
	defer func() {
		cc.err = err
		cc.Close()
	}()
	var f http2Frame
	for {
		if f, err = cc.fr.ReadFrame(); err != nil {
			return tools.WrapError(err, "ReadFrame")
		}
		switch f := f.(type) {
		case *http2MetaHeadersFrame:
			if cc.http2clientStream.resp, err = cc.loop.handleResponse(cc.http2clientStream, f); err != nil {
				return tools.WrapError(err, "handleResponse")
			}
			cc.http2clientStream.headCnl()
		case *http2DataFrame:
			if _, err = cc.loop.processData(cc.http2clientStream, f); err != nil {
				return tools.WrapError(err, "processData")
			}
		case *http2GoAwayFrame:
			if err = cc.loop.processGoAway(f); err != nil {
				return tools.WrapError(err, "processGoAway")
			}
		case *http2RSTStreamFrame:
			if err = cc.loop.processResetStream(f); err != nil {
				return tools.WrapError(err, "processResetStream")
			}
		case *http2SettingsFrame:
			if err = cc.loop.processSettings(f); err != nil {
				return tools.WrapError(err, "processSettings")
			}
		case *http2PushPromiseFrame:
			if err = cc.loop.processPushPromise(); err != nil {
				return tools.WrapError(err, "processPushPromise")
			}
		case *http2WindowUpdateFrame:
			if err = cc.loop.processWindowUpdate(f); err != nil {
				return tools.WrapError(err, "processWindowUpdate")
			}
		case *http2PingFrame:
			if err = cc.loop.processPing(f); err != nil {
				return tools.WrapError(err, "processPing")
			}
		default:
		}
	}
}

type gospiderOption struct {
	orderHeaders      []string
	initialSetting    []ja3.Setting
	priority          ja3.Priority
	connFlow          uint32
	streamFlow        uint32
	headerTableSize   uint32
	maxHeaderListSize uint32
}

func clearOrderHeaders(headers []string) []string {
	orderHeaders := []string{}
	if len(headers) == 0 {
		for _, val := range ja3.DefaultOrderHeaders() {
			val = strings.ToLower(val)
			if !slices.Contains(orderHeaders, val) {
				orderHeaders = append(orderHeaders, val)
			}
		}
	} else {
		for _, val := range headers {
			val = strings.ToLower(val)
			if !slices.Contains(orderHeaders, val) {
				orderHeaders = append(orderHeaders, val)
			}
		}
		kks := ja3.DefaultOrderHeadersWithH2()
		for i := len(kks) - 1; i >= 0; i-- {
			if !slices.Contains(orderHeaders, kks[i]) {
				orderHeaders = slices.Insert(orderHeaders, 0, kks[i])
			}
		}
	}
	return orderHeaders
}
func spec2option(h2Ja3Spec ja3.H2Ja3Spec) gospiderOption {
	var headerTableSize uint32 = 65536
	var maxHeaderListSize uint32 = 262144
	var streamFlow uint32 = 6291456

	if h2Ja3Spec.InitialSetting != nil {
		for _, setting := range h2Ja3Spec.InitialSetting {
			switch setting.Id {
			case 1:
				headerTableSize = setting.Val
			case 6:
				maxHeaderListSize = setting.Val
			case 4:
				streamFlow = setting.Val
			}
		}
	} else {
		h2Ja3Spec.InitialSetting = []ja3.Setting{
			{Id: 1, Val: headerTableSize},
			{Id: 2, Val: 0},
			{Id: 3, Val: 1000},
			{Id: 4, Val: 6291456},
			{Id: 6, Val: maxHeaderListSize},
		}
	}
	if !h2Ja3Spec.Priority.Exclusive && h2Ja3Spec.Priority.StreamDep == 0 && h2Ja3Spec.Priority.Weight == 0 {
		h2Ja3Spec.Priority = ja3.Priority{
			Exclusive: true,
			StreamDep: 0,
			Weight:    255,
		}
	}
	if h2Ja3Spec.ConnFlow == 0 {
		h2Ja3Spec.ConnFlow = 15663105
	}
	h2Ja3Spec.OrderHeaders = clearOrderHeaders(h2Ja3Spec.OrderHeaders)
	return gospiderOption{
		orderHeaders:      h2Ja3Spec.OrderHeaders,
		initialSetting:    h2Ja3Spec.InitialSetting,
		priority:          h2Ja3Spec.Priority,
		streamFlow:        streamFlow,
		connFlow:          h2Ja3Spec.ConnFlow,
		headerTableSize:   headerTableSize,
		maxHeaderListSize: maxHeaderListSize,
	}
}
func NewClientConn(closefun func(), c net.Conn, h2Ja3Spec ja3.H2Ja3Spec) (*Http2ClientConn, error) {
	ctx, cnl := context.WithCancel(context.TODO())
	cc := &Http2ClientConn{
		closeFunc:             closefun,
		spec:                  spec2option(h2Ja3Spec),
		ctx:                   ctx,
		cnl:                   cnl,
		tconn:                 c,
		nextStreamID:          1,
		maxFrameSize:          16 << 10,           // spec default
		initialWindowSize:     65535,              // spec default
		peerMaxHeaderListSize: 0xffffffffffffffff, // "infinite", per spec. Use 2^64-1 instead.
	}
	cc.flow.add(int32(cc.initialWindowSize))
	cc.bw = bufio.NewWriter(c)
	cc.fr = http2NewFramer(cc.bw, bufio.NewReader(c))
	cc.fr.ReadMetaHeaders = hpack.NewDecoder(cc.spec.headerTableSize, nil)
	cc.fr.MaxHeaderListSize = maxHeaderListSize
	cc.henc = hpack.NewEncoder(&cc.hbuf)
	cc.henc.SetMaxDynamicTableSizeLimit(cc.spec.headerTableSize)
	initialSettings := make([]http2Setting, len(cc.spec.initialSetting))
	for i, setting := range cc.spec.initialSetting {
		initialSettings[i] = http2Setting{ID: http2SettingID(setting.Id), Val: setting.Val}
	}

	// initialSettings := []http2Setting{
	// 	// {ID: http2SettingEnablePush, Val: 0},
	// 	{ID: http2SettingInitialWindowSize, Val: 4194304},
	// }
	// initialSettings = append(initialSettings, http2Setting{ID: http2SettingMaxFrameSize, Val: 16384})
	// initialSettings = append(initialSettings, http2Setting{ID: http2SettingMaxHeaderListSize, Val: 10 << 20})
	// initialSettings = append(initialSettings, http2Setting{ID: http2SettingHeaderTableSize, Val: 4096})

	if _, err := cc.bw.Write(http2clientPreface); err != nil {
		return nil, err
	}
	if err := cc.fr.WriteSettings(initialSettings...); err != nil {
		return nil, err
	}
	if err := cc.fr.WriteWindowUpdate(0, cc.spec.connFlow); err != nil {
		return nil, err
	}
	cc.inflow.init(int32(cc.spec.connFlow) + int32(cc.initialWindowSize))
	if err := cc.bw.Flush(); err != nil {
		return nil, err
	}
	cc.loop = &http2clientConnReadLoop{cc: cc}
	go cc.run()
	return cc, nil
}

// SetDoNotReuse marks cc as not reusable for future HTTP requests.

func (cc *Http2ClientConn) Close() error {
	if cc.closeFunc != nil {
		cc.closeFunc()
	}
	cc.cnl()
	cc.tconn.Close()
	cc.http2clientStream.headCnl()
	return nil
}

// CanTakeNewRequest reports whether the connection can take a new request,
// meaning it has not been closed or received or sent a GOAWAY.
//
// If the caller is going to immediately make a new request on this
// connection, use ReserveNewRequest instead.

// ClientConnState describes the state of a ClientConn.
type Http2ClientConnState struct {

	// StreamsActive is how many streams are active.

	// StreamsReserved is how many streams have been reserved via
	// ClientConn.ReserveNewRequest.
	StreamsReserved int

	// StreamsPending is how many requests have been sent in excess
	// of the peer's advertised MaxConcurrentStreams setting and
	// are waiting for other streams to complete.
	StreamsPending int

	// MaxConcurrentStreams is how many concurrent streams the
	// peer advertised as acceptable. Zero means no SETTINGS
	// frame has been received yet.
	MaxConcurrentStreams uint32
}

func http2commaSeparatedTrailers(req *http.Request) (string, error) {
	keys := make([]string, 0, len(req.Trailer))
	for k := range req.Trailer {
		k = http2canonicalHeader(k)
		switch k {
		case "Transfer-Encoding", "Trailer", "Content-Length":
			return "", fmt.Errorf("invalid Trailer key %q", k)
		}
		keys = append(keys, k)
	}
	if len(keys) > 0 {
		sort.Strings(keys)
		return strings.Join(keys, ","), nil
	}
	return "", nil
}

// actualContentLength returns a sanitized version of
// req.ContentLength, where 0 actually means zero (not unknown) and -1
// means unknown.
func http2actualContentLength(req *http.Request) int64 {
	if req.Body == nil || req.Body == http.NoBody {
		return 0
	}
	if req.ContentLength != 0 {
		return req.ContentLength
	}
	return -1
}

func (cc *Http2ClientConn) DoRequest(req *http.Request, orderHeaders []string) (*http.Response, error) {
	if orderHeaders != nil {
		orderHeaders = clearOrderHeaders(orderHeaders)
	} else if cc.spec.orderHeaders != nil {
		orderHeaders = cc.spec.orderHeaders
	}
	ctx := req.Context()
	headCtx, headCnl := context.WithCancel(ctx)
	reader, writer := io.Pipe()
	cs := &http2clientStream{
		cc:                   cc,
		ctx:                  ctx,
		headCtx:              headCtx,
		headCnl:              headCnl,
		reqBody:              req.Body,
		reqBodyContentLength: http2actualContentLength(req),
		bodyReader:           reader,
		bodyWriter:           writer,
	}
	cc.http2clientStream = cs
	err := cs.writeRequest(req, orderHeaders)
	if err != nil {
		return nil, err
	}
	if cs.reqBody != nil {
		defer cs.reqBody.Close()
	}
	select {
	case <-cs.headCtx.Done():
		cs.resp.Request = req
		return cs.resp, cc.err
	case <-ctx.Done():
		if cc.err != nil {
			return nil, cc.err
		}
		return nil, ctx.Err()
	case <-cc.ctx.Done():
		if cc.err != nil {
			return nil, cc.err
		}
		return nil, cc.ctx.Err()
	}
}

// doRequest runs for the duration of the request lifetime.
//
// It sends the request and performs post-request cleanup (closing Request.Body, etc.).
// writeRequest sends a request.
//
// It returns nil after the request is written, the response read,
// and the request stream is half-closed by the peer.
//
// It returns non-nil if the request ends otherwise.
// If the returned error is StreamError, the error Code may be used in resetting the stream.
func (cs *http2clientStream) writeRequest(req *http.Request, orderHeaders []string) (err error) {
	cc := cs.cc
	cc.addStreamLocked(cs) // assigns stream ID
	err = cs.encodeAndWriteHeaders(req, orderHeaders)
	if err != nil {
		return err
	}
	if cs.reqBodyContentLength != 0 {
		return cs.writeRequestBody(req)
	}
	return nil
}

func (cs *http2clientStream) encodeAndWriteHeaders(req *http.Request, orderHeaders []string) error {
	cc := cs.cc
	trailers, err := http2commaSeparatedTrailers(req)
	if err != nil {
		return err
	}
	hasTrailers := trailers != ""
	contentLen := http2actualContentLength(req)
	hasBody := contentLen != 0
	hdrs, err := cc.encodeHeaders(req, trailers, contentLen, orderHeaders)
	if err != nil {
		return err
	}
	// Write the request.
	endStream := !hasBody && !hasTrailers
	err = cc.writeHeaders(cs.ID, endStream, int(cc.maxFrameSize), hdrs)
	return err
}

func (cc *Http2ClientConn) writeHeaders(streamID uint32, endStream bool, maxFrameSize int, hdrs []byte) error {
	first := true // first frame written (HEADERS is first, then CONTINUATION)
	for len(hdrs) > 0 {
		chunk := hdrs
		if len(chunk) > maxFrameSize {
			chunk = chunk[:maxFrameSize]
		}
		hdrs = hdrs[len(chunk):]
		endHeaders := len(hdrs) == 0
		if first {
			cc.fr.WriteHeaders(http2HeadersFrameParam{
				StreamID:      streamID,
				BlockFragment: chunk,
				EndStream:     endStream,
				EndHeaders:    endHeaders,
				Priority: http2PriorityParam{
					StreamDep: cc.spec.priority.StreamDep,
					Exclusive: cc.spec.priority.Exclusive,
					Weight:    cc.spec.priority.Weight,
				},
			})
			first = false
		} else {
			cc.fr.WriteContinuation(streamID, endHeaders, chunk)
		}
	}
	return cc.bw.Flush()
}

// internal error values; they don't escape to callers
var (
	errHttp2ReqBodyTooLong = errors.New("http2: request body larger than specified content length")
)

// frameScratchBufferLen returns the length of a buffer to use for
// outgoing request bodies to read/write to/from.
//
// It returns max(1, min(peer's advertised max frame size,
// Request.ContentLength+1, 512KB)).
func (cs *http2clientStream) frameScratchBufferLen(maxFrameSize int) int {
	const max = 512 << 10
	n := int64(maxFrameSize)
	if n > max {
		n = max
	}
	if cl := cs.reqBodyContentLength; cl != -1 && cl+1 < n {
		n = cl + 1
	}
	if n < 1 {
		return 1
	}
	return int(n) // doesn't truncate; max is 512K
}

var http2bufPools [7]sync.Pool // of *[]byte

func http2bufPoolIndex(size int) int {
	if size <= 16384 {
		return 0
	}
	size -= 1
	bits := bits.Len(uint(size))
	index := bits - 14
	if index >= len(http2bufPools) {
		return len(http2bufPools) - 1
	}
	return index
}

func (cs *http2clientStream) writeRequestBody(req *http.Request) (err error) {
	cc := cs.cc
	body := cs.reqBody
	sentEnd := false // whether we sent the final DATA frame w/ END_STREAM

	hasTrailers := req.Trailer != nil
	remainLen := cs.reqBodyContentLength
	hasContentLen := remainLen != -1

	maxFrameSize := int(cc.maxFrameSize)

	// Scratch buffer for reading into & writing from.
	scratchLen := cs.frameScratchBufferLen(maxFrameSize)
	var buf []byte
	index := http2bufPoolIndex(scratchLen)
	if bp, ok := http2bufPools[index].Get().(*[]byte); ok && len(*bp) >= scratchLen {
		defer http2bufPools[index].Put(bp)
		buf = *bp
	} else {
		buf = make([]byte, scratchLen)
		defer http2bufPools[index].Put(&buf)
	}
	var sawEOF bool
	for !sawEOF {
		n, err := body.Read(buf)
		if hasContentLen {
			remainLen -= int64(n)
			if remainLen == 0 && err == nil {
				var scratch [1]byte
				var n1 int
				n1, err = body.Read(scratch[:])
				remainLen -= int64(n1)
			}
			if remainLen < 0 {
				err = errHttp2ReqBodyTooLong
				return err
			}
		}
		if err != nil {
			switch {
			case err == io.EOF:
				sawEOF = true
				err = nil
			default:
				return err
			}
		}

		remain := buf[:n]
		for len(remain) > 0 && err == nil {
			var allowed int32
			allowed, err = cs.awaitFlowControl(len(remain))
			if err != nil {
				return err
			}
			data := remain[:allowed]
			remain = remain[allowed:]
			sentEnd = sawEOF && len(remain) == 0 && !hasTrailers
			err = cc.fr.WriteData(cs.ID, sentEnd, data)
			if err == nil {
				err = cc.bw.Flush()
			}
		}
		if err != nil {
			return err
		}
	}

	if sentEnd {
		return nil
	}
	trailer := req.Trailer
	// err = cs.abortErr
	if err != nil {
		return err
	}
	var trls []byte
	if len(trailer) > 0 {
		trls, err = cc.encodeTrailers(trailer)
		if err != nil {
			return err
		}
	}

	if len(trls) > 0 {
		err = cc.writeHeaders(cs.ID, true, maxFrameSize, trls)
	} else {
		err = cc.fr.WriteData(cs.ID, true, nil)
	}
	if ferr := cc.bw.Flush(); ferr != nil && err == nil {
		err = ferr
	}
	return err
}

func (cs *http2clientStream) awaitFlowControl(maxBytes int) (taken int32, err error) {
	cc := cs.cc
	for {
		if a := cs.flow.available(); a > 0 {
			take := a
			if int(take) > maxBytes {

				take = int32(maxBytes) // can't truncate int; take is int32
			}
			if take > int32(cc.maxFrameSize) {
				take = int32(cc.maxFrameSize)
			}
			cs.flow.take(take)
			return take, nil
		}
	}
}
func http2validateHeaders(hdrs http.Header) string {
	for k, vv := range hdrs {
		if !httpguts.ValidHeaderFieldName(k) {
			return fmt.Sprintf("name %q", k)
		}
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				// Don't include the value in the error,
				// because it may be sensitive.
				return fmt.Sprintf("value for header %q", k)
			}
		}
	}
	return ""
}

var errHttp2NilRequestURL = errors.New("http2: Request.URI is nil")

// requires cc.wmu be held.
func (cc *Http2ClientConn) encodeHeaders(req *http.Request, trailers string, contentLength int64, orderHeaders []string) ([]byte, error) {
	cc.hbuf.Reset()
	if req.URL == nil {
		return nil, errHttp2NilRequestURL
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	host, err := httpguts.PunycodeHostPort(host)
	if err != nil {
		return nil, err
	}
	if !httpguts.ValidHostHeader(host) {
		return nil, errors.New("http2: invalid Host header")
	}

	var path string
	if req.Method != "CONNECT" {
		path = req.URL.RequestURI()
		if !http2validPseudoPath(path) {
			orig := path
			path = strings.TrimPrefix(path, req.URL.Scheme+"://"+host)
			if !http2validPseudoPath(path) {
				if req.URL.Opaque != "" {
					return nil, fmt.Errorf("invalid request :path %q from URL.Opaque = %q", orig, req.URL.Opaque)
				} else {
					return nil, fmt.Errorf("invalid request :path %q", orig)
				}
			}
		}
	}

	// Check for any invalid headers+trailers and return an error before we
	// potentially pollute our hpack state. (We want to be able to
	// continue to reuse the hpack encoder for future requests)
	if err := http2validateHeaders(req.Header); err != "" {
		return nil, fmt.Errorf("invalid HTTP header %s", err)
	}
	if err := http2validateHeaders(req.Trailer); err != "" {
		return nil, fmt.Errorf("invalid HTTP trailer %s", err)
	}

	enumerateHeaders := func(replaceF func(name, value string)) {
		gospiderHeaders := map[string][]string{}
		f := func(name, value string) {
			name = strings.ToLower(name)
			gospiderHeaders[name] = append(gospiderHeaders[name], value)
		}
		// 8.1.2.3 Request Pseudo-Header Fields
		// The :path pseudo-header field includes the path and query parts of the
		// target URI (the path-absolute production and optionally a '?' character
		// followed by the query production, see Sections 3.3 and 3.4 of
		// [RFC3986]).
		f(":authority", host)
		m := req.Method
		if m == "" {
			m = http.MethodGet
		}
		f(":method", m)
		if req.Method != "CONNECT" {
			f(":path", path)
			f(":scheme", req.URL.Scheme)
		}
		if trailers != "" {
			f("trailer", trailers)
		}
		for k, vv := range req.Header {
			if http2asciiEqualFold(k, "host") ||
				http2asciiEqualFold(k, "content-length") ||
				http2asciiEqualFold(k, "connection") ||
				http2asciiEqualFold(k, "proxy-connection") ||
				http2asciiEqualFold(k, "transfer-encoding") ||
				http2asciiEqualFold(k, "upgrade") ||
				http2asciiEqualFold(k, "keep-alive") {
				continue
			} else if http2asciiEqualFold(k, "cookie") {
				// Per 8.1.2.5 To allow for better compression efficiency, the
				// Cookie header field MAY be split into separate header fields,
				// each with one or more cookie-pairs.
				for _, v := range vv {
					for {
						p := strings.IndexByte(v, ';')
						if p < 0 {
							break
						}
						f("cookie", v[:p])
						p++
						// strip space after semicolon if any.
						for p+1 <= len(v) && v[p] == ' ' {
							p++
						}
						v = v[p:]
					}
					if len(v) > 0 {
						f("cookie", v)
					}
				}
				continue
			}
			for _, v := range vv {
				f(k, v)
			}
		}
		if http2shouldSendReqContentLength(req.Method, contentLength) {
			f("content-length", strconv.FormatInt(contentLength, 10))
		}
		for _, kk := range orderHeaders {
			if vvs, ok := gospiderHeaders[kk]; ok {
				for _, vv := range vvs {
					replaceF(kk, vv)
				}
			}
		}
		for kk, vvs := range gospiderHeaders {
			if !slices.Contains(orderHeaders, kk) {
				for _, vv := range vvs {
					replaceF(kk, vv)
				}
			}
		}
	}

	// Do a first pass over the headers counting bytes to ensure
	// we don't exceed cc.peerMaxHeaderListSize. This is done as a
	// separate pass before encoding the headers to prevent
	// modifying the hpack state.
	hlSize := uint64(0)
	enumerateHeaders(func(name, value string) {
		hf := hpack.HeaderField{Name: name, Value: value}
		hlSize += uint64(hf.Size())
	})

	if hlSize > cc.peerMaxHeaderListSize {
		return nil, errHttp2RequestHeaderListSize
	}
	// Header list size is ok. Write the headers.
	enumerateHeaders(func(name, value string) {
		name, ascii := http2lowerHeader(name)
		if !ascii {
			// Skip writing invalid headers. Per RFC 7540, Section 8.1.2, header
			// field names have to be ASCII characters (just as in HTTP/1.x).
			return
		}
		cc.writeHeader(name, value)
	})

	return cc.hbuf.Bytes(), nil
}

// shouldSendReqContentLength reports whether the http2.Transport should send
// a "content-length" request header. This logic is basically a copy of the net/http
// transferWriter.shouldSendContentLength.
// The contentLength is the corrected contentLength (so 0 means actually 0, not unknown).
// -1 means unknown.
func http2shouldSendReqContentLength(method string, contentLength int64) bool {
	if contentLength > 0 {
		return true
	}
	if contentLength < 0 {
		return false
	}
	// For zero bodies, whether we send a content-length depends on the method.
	// It also kinda doesn't matter for http2 either way, with END_STREAM.
	switch method {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

func (cc *Http2ClientConn) encodeTrailers(trailer http.Header) ([]byte, error) {
	cc.hbuf.Reset()

	hlSize := uint64(0)
	for k, vv := range trailer {
		for _, v := range vv {
			hf := hpack.HeaderField{Name: k, Value: v}
			hlSize += uint64(hf.Size())
		}
	}
	if hlSize > cc.peerMaxHeaderListSize {
		return nil, errHttp2RequestHeaderListSize
	}

	for k, vv := range trailer {
		lowKey, ascii := http2lowerHeader(k)
		if !ascii {
			continue
		}
		for _, v := range vv {
			cc.writeHeader(lowKey, v)
		}
	}
	return cc.hbuf.Bytes(), nil
}

func (cc *Http2ClientConn) writeHeader(name, value string) {
	cc.henc.WriteField(hpack.HeaderField{Name: name, Value: value})
}

// requires cc.mu be held.
func (cc *Http2ClientConn) addStreamLocked(cs *http2clientStream) {
	cs.flow.add(int32(cc.initialWindowSize))
	cs.flow.setConnFlow(&cc.flow)
	cs.inflow.init(int32(cc.spec.streamFlow))
	cs.ID = cc.nextStreamID
	cc.nextStreamID += 2
}

// clientConnReadLoop is the state owned by the clientConn's frame-reading readLoop.
type http2clientConnReadLoop struct {
	cc *Http2ClientConn
}

func (rl *http2clientConnReadLoop) handleResponse(cs *http2clientStream, f *http2MetaHeadersFrame) (*http.Response, error) {
	if f.Truncated {
		return nil, errHttp2ResponseHeaderListSize
	}
	status := f.PseudoValue("status")
	if status == "" {
		return nil, errors.New("malformed response from server: missing status pseudo header")
	}
	statusCode, err := strconv.Atoi(status)
	if err != nil {
		return nil, errors.New("malformed response from server: malformed non-numeric status pseudo header")
	}
	regularFields := f.RegularFields()
	strs := make([]string, len(regularFields))
	header := make(http.Header, len(regularFields))
	res := &http.Response{
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		Header:     header,
		StatusCode: statusCode,
		Status:     status + " " + http.StatusText(statusCode),
	}
	for _, hf := range regularFields {
		key := http2canonicalHeader(hf.Name)
		if key == "Trailer" {
			t := res.Trailer
			if t == nil {
				t = make(http.Header)
				res.Trailer = t
			}
			http2foreachHeaderElement(hf.Value, func(v string) {
				t[http2canonicalHeader(v)] = nil
			})
		} else {
			vv := header[key]
			if vv == nil && len(strs) > 0 {
				vv, strs = strs[:1:1], strs[1:]
				vv[0] = hf.Value
				header[key] = vv
			} else {
				header[key] = append(vv, hf.Value)
			}
		}
	}
	res.ContentLength = -1
	if clens := res.Header["Content-Length"]; len(clens) >= 1 {
		if cl, err := strconv.ParseUint(clens[0], 10, 63); err == nil {
			res.ContentLength = int64(cl)
		}
	} else if f.StreamEnded() {
		res.ContentLength = 0
	}

	if f.StreamEnded() {
		if res.ContentLength > 0 {
			res.Body = http2missingBody{}
		} else {
			res.Body = http2noBody
		}
		return res, nil
	}
	res.Body = http2transportResponseBody{cs}
	return res, nil
}

type http2transportResponseBody struct {
	cs *http2clientStream
}

func (b http2transportResponseBody) Read(p []byte) (n int, err error) {
	cs := b.cs
	cc := cs.cc
	n, err = b.cs.bodyReader.Read(p)
	if n == 0 {
		return
	}
	connAdd := cc.inflow.add(n)
	var streamAdd int32
	if err == nil { // No need to refresh if the stream is over or failed.
		streamAdd = cs.inflow.add(n)
	}
	if connAdd != 0 || streamAdd != 0 {
		if connAdd != 0 {
			cc.fr.WriteWindowUpdate(0, http2mustUint31(connAdd))
		}
		if streamAdd != 0 {
			cc.fr.WriteWindowUpdate(cs.ID, http2mustUint31(streamAdd))
		}
		cc.bw.Flush()
	}
	return
}
func (b http2transportResponseBody) Close() error {
	return b.cs.bodyReader.Close()
}
func (rl *http2clientConnReadLoop) processData(cs *http2clientStream, f *http2DataFrame) (bool, error) {
	cc := rl.cc
	data := f.Data()
	if f.Length > 0 {
		if !http2takeInflows(&cc.inflow, &cs.inflow, f.Length) {
			return false, http2ConnectionError(errHttp2CodeFlowControl)
		}
		// Return any padded flow control now, since we won't
		// refund it later on body reads.
		var refund int
		if pad := int(f.Length) - len(data); pad > 0 {
			refund += pad
		}
		if len(data) > 0 {
			if _, err := cs.bodyWriter.Write(data); err != nil {
				return false, err
			}
		}
		sendConn := cc.inflow.add(refund)
		sendStream := cs.inflow.add(refund)
		if sendConn > 0 || sendStream > 0 {
			if sendConn > 0 {
				cc.fr.WriteWindowUpdate(0, uint32(sendConn))
			}
			if sendStream > 0 {
				cc.fr.WriteWindowUpdate(cs.ID, uint32(sendStream))
			}
			cc.bw.Flush()
		}
	}
	isEnd := f.StreamEnded()
	if isEnd {
		cs.bodyWriter.CloseWithError(io.EOF)
	}
	return isEnd, nil
}
func (rl *http2clientConnReadLoop) processGoAway(f *http2GoAwayFrame) error {
	if f.ErrCode == 0 {
		return nil
	}
	return fmt.Errorf("http2: server sent GOAWAY with error code %v", f.ErrCode)
}
func (rl *http2clientConnReadLoop) processSettings(f *http2SettingsFrame) error {
	cc := rl.cc
	if err := rl.processSettingsNoWrite(f); err != nil {
		return err
	}
	if !f.IsAck() {
		cc.fr.WriteSettingsAck()
		cc.bw.Flush()
	}
	return nil
}
func (rl *http2clientConnReadLoop) processSettingsNoWrite(f *http2SettingsFrame) error {
	cc := rl.cc
	err := f.ForeachSetting(func(s http2Setting) error {
		switch s.ID {
		case http2SettingMaxFrameSize: //MAX_FRAME_SIZE
			cc.maxFrameSize = s.Val
		case http2SettingMaxHeaderListSize: //MAX_HEADER_LIST_SIZE
			cc.peerMaxHeaderListSize = uint64(s.Val)
		case http2SettingInitialWindowSize: //INITIAL_WINDOW_SIZE
			cc.initialWindowSize = s.Val
		case http2SettingHeaderTableSize: //HEADER_TABLE_SIZE
			cc.henc.SetMaxDynamicTableSize(s.Val)
		default:
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
func (rl *http2clientConnReadLoop) processWindowUpdate(f *http2WindowUpdateFrame) error {
	fl := &rl.cc.flow
	if !fl.add(int32(f.Increment)) {
		return http2ConnectionError(errHttp2CodeFlowControl)
	}
	return nil
}
func (rl *http2clientConnReadLoop) processResetStream(f *http2RSTStreamFrame) error {
	return fmt.Errorf("stream error: %v", f.ErrCode)
}
func (cc *Http2ClientConn) Ping(ctx context.Context) error {
	var p [8]byte
	rand.Read(p[:])
	if pingError := cc.fr.WritePing(false, p); pingError != nil {
		return pingError
	}
	if pingError := cc.bw.Flush(); pingError != nil {
		return pingError
	}
	return nil
}
func (rl *http2clientConnReadLoop) processPing(f *http2PingFrame) error {
	cc := rl.cc
	if err := cc.fr.WritePing(true, f.Data); err != nil {
		return err
	}
	return cc.bw.Flush()
}
func (rl *http2clientConnReadLoop) processPushPromise() error {
	return http2ConnectionError(errHttp2CodeProtocol)
}

var (
	errHttp2ResponseHeaderListSize = errors.New("http2: response header list larger than advertised limit")
	errHttp2RequestHeaderListSize  = errors.New("http2: request header list larger than peer's advertised limit")
)
var http2noBody io.ReadCloser = http2noBodyReader{}

type http2noBodyReader struct{}

func (http2noBodyReader) Close() error             { return nil }
func (http2noBodyReader) Read([]byte) (int, error) { return 0, io.EOF }

type http2missingBody struct{}

func (http2missingBody) Close() error             { return nil }
func (http2missingBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
