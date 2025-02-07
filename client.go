package http2

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

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

func http2lower(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func http2isASCIIPrint(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

func http2asciiToLower(s string) (lower string, ok bool) {
	if !http2isASCIIPrint(s) {
		return "", false
	}
	return strings.ToLower(s), true
}

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

type http2ConnectionError errHttp2Code

func (e http2ConnectionError) Error() string {
	return fmt.Sprintf("connection error: %d", errHttp2Code(e))
}

type http2inflow struct {
	initconn   int32
	initstream int32
	conn       int32
	stream     int32
	streamRecv int32
}

func (f *http2inflow) initConn(n int32) {
	f.initconn = n
	f.conn = n
}
func (f *http2inflow) initStream(n int32) {
	f.initstream = n
	f.stream = n
	f.streamRecv = 0
}

func (f *http2inflow) add(dataLength, recvLength int32) (connAdd, streamAdd int32) {
	f.conn -= recvLength
	f.stream -= recvLength
	f.streamRecv += recvLength

	unset := dataLength - f.streamRecv
	if f.conn < unset {
		connAdd = f.initconn - f.conn
	}
	if f.stream < unset {
		streamAdd = f.initstream - f.stream
	}
	return
}

const http2frameHeaderLen = 9

var http2padZeros = make([]byte, 255)

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

type http2Flags uint8

func (f http2Flags) Has(v http2Flags) bool {
	return (f & v) == v
}

const (
	http2FlagDataEndStream http2Flags = 0x1
	http2FlagDataPadded    http2Flags = 0x8

	http2FlagHeadersEndStream  http2Flags = 0x1
	http2FlagHeadersEndHeaders http2Flags = 0x4
	http2FlagHeadersPadded     http2Flags = 0x8
	http2FlagHeadersPriority   http2Flags = 0x20

	http2FlagSettingsAck http2Flags = 0x1

	http2FlagPingAck http2Flags = 0x1

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

type http2frameParser func(fc *http2frameCache, fh http2FrameHeader, countError func(string), payload []byte) (http2Frame, error)

func http2parseHeadersFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (_ http2Frame, err error) {
	hf := &http2HeadersFrame{
		http2FrameHeader: fh,
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
		p, hf.Priority.Weight, err = http2readByte(p)
		if err != nil {
			countError("frame_headers_prio_weight_short")
			return nil, err
		}
		hf.Priority.StreamDep = v & 0x7fffffff
		hf.Priority.Exclusive = (v != hf.Priority.StreamDep)
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

type http2FrameHeader struct {
	Type     http2FrameType
	Flags    http2Flags
	Length   uint32
	StreamID uint32
}

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
	}, nil
}

type http2Frame interface {
	Header() http2FrameHeader
}

type http2Framer struct {
	r                   io.Reader
	headerBuf           [http2frameHeaderLen]byte
	getReadBuf          func(size uint32) []byte
	readBuf             []byte
	w                   io.Writer
	wbuf                []byte
	ReadMetaHeaders     *hpack.Decoder
	logReads, logWrites bool
	debugFramer         *http2Framer
	debugFramerBuf      *bytes.Buffer
	frameCache          *http2frameCache
}

func (f *http2Framer) startWrite(ftype http2FrameType, flags http2Flags, streamID uint32) {

	f.wbuf = append(f.wbuf[:0],
		0,
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
		f.debugFramer.logReads = false

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

func http2NewFramer(w io.Writer, r io.Reader) *http2Framer {
	fr := &http2Framer{
		w: w,
		r: r,
	}
	fr.getReadBuf = func(size uint32) []byte {
		if cap(fr.readBuf) >= int(size) {
			return fr.readBuf[:size]
		}
		fr.readBuf = make([]byte, size)
		return fr.readBuf
	}
	return fr
}

var errHttp2FrameTooLarge = errors.New("http2: frame too large")

func (fr *http2Framer) ReadFrame() (http2Frame, error) {
	fh, err := http2readFrameHeader(fr.headerBuf[:], fr.r)
	if err != nil {
		return nil, err
	}
	payload := fr.getReadBuf(fh.Length)
	if _, err := io.ReadFull(fr.r, payload); err != nil {
		return nil, err
	}
	f, err := http2typeFrameParser(fh.Type)(fr.frameCache, fh, nil, payload)
	if err != nil {
		return nil, err
	}
	if fh.Type == http2FrameHeaders && fr.ReadMetaHeaders != nil {
		return fr.readMetaFrame(f.(*http2HeadersFrame))
	}
	return f, nil
}

type http2DataFrame struct {
	http2FrameHeader
	data []byte
}

func (f *http2DataFrame) StreamEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagDataEndStream)
}

func (f *http2DataFrame) Data() []byte {
	return f.data
}

func http2parseDataFrame(fc *http2frameCache, fh http2FrameHeader, countError func(string), payload []byte) (http2Frame, error) {
	if fh.StreamID == 0 {
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
		countError("frame_data_pad_too_big")
		return nil, errors.New("pad size larger than data payload")
	}
	f.data = payload[:len(payload)-int(padSize)]
	return f, nil
}

var (
	errHttp2PadLength = errors.New("pad length too large")
)

func (f *http2Framer) WriteData(streamID uint32, endStream bool, data []byte) error {
	return f.WriteDataPadded(streamID, endStream, data, nil)
}

func (f *http2Framer) WriteDataPadded(streamID uint32, endStream bool, data, pad []byte) error {
	if err := f.startWriteDataPadded(streamID, endStream, data, pad); err != nil {
		return err
	}
	return f.endWrite()
}

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

type http2SettingsFrame struct {
	http2FrameHeader
	p []byte
}

func http2parseSettingsFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	if fh.Flags.Has(http2FlagSettingsAck) && fh.Length > 0 {
		countError("frame_settings_ack_with_length")
		return nil, http2ConnectionError(errHttp2CodeFrameSize)
	}
	if fh.StreamID != 0 {
		countError("frame_settings_has_stream")
		return nil, http2ConnectionError(errHttp2CodeProtocol)
	}
	if len(p)%6 != 0 {
		countError("frame_settings_mod_6")
		return nil, http2ConnectionError(errHttp2CodeFrameSize)
	}
	f := &http2SettingsFrame{http2FrameHeader: fh, p: p}
	if v, ok := f.Value(Http2SettingInitialWindowSize); ok && v > (1<<31)-1 {
		countError("frame_settings_window_size_too_big")
		return nil, http2ConnectionError(errHttp2CodeFlowControl)
	}
	return f, nil
}

func (f *http2SettingsFrame) IsAck() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagSettingsAck)
}

func (f *http2SettingsFrame) Value(id http2SettingID) (v uint32, ok bool) {
	for i := 0; i < f.NumSettings(); i++ {
		if s := f.Setting(i); s.ID == id {
			return s.Val, true
		}
	}
	return 0, false
}

func (f *http2SettingsFrame) Setting(i int) http2Setting {
	buf := f.p
	return http2Setting{
		ID:  http2SettingID(binary.BigEndian.Uint16(buf[i*6 : i*6+2])),
		Val: binary.BigEndian.Uint32(buf[i*6+2 : i*6+6]),
	}
}

func (f *http2SettingsFrame) NumSettings() int { return len(f.p) / 6 }

func (f *http2SettingsFrame) HasDuplicates() bool {
	num := f.NumSettings()
	if num == 0 {
		return false
	}

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

func (f *http2SettingsFrame) ForeachSetting(fn func(http2Setting) error) error {
	for i := 0; i < f.NumSettings(); i++ {
		if err := fn(f.Setting(i)); err != nil {
			return err
		}
	}
	return nil
}

func (f *http2Framer) WriteSettings(settings ...http2Setting) error {
	f.startWrite(http2FrameSettings, 0, 0)
	for _, s := range settings {
		f.writeUint16(uint16(s.ID))
		f.writeUint32(s.Val)
	}
	return f.endWrite()
}

func (f *http2Framer) WriteSettingsAck() error {
	f.startWrite(http2FrameSettings, http2FlagSettingsAck, 0)
	return f.endWrite()
}

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

type http2GoAwayFrame struct {
	http2FrameHeader
	LastStreamID uint32
	ErrCode      errHttp2Code
	debugData    []byte
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

type http2UnknownFrame struct {
	http2FrameHeader
	p []byte
}

func (f *http2UnknownFrame) Payload() []byte {
	return f.p
}

func http2parseUnknownFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	return &http2UnknownFrame{fh, p}, nil
}

type http2WindowUpdateFrame struct {
	http2FrameHeader
	Increment uint32
}

func http2parseWindowUpdateFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	if len(p) != 4 {
		countError("frame_windowupdate_bad_len")
		return nil, http2ConnectionError(errHttp2CodeFrameSize)
	}
	return &http2WindowUpdateFrame{
		http2FrameHeader: fh,
		Increment:        binary.BigEndian.Uint32(p[:4]) & 0x7fffffff,
	}, nil
}

func (f *http2Framer) WriteWindowUpdate(streamID, incr uint32) error {
	f.startWrite(http2FrameWindowUpdate, 0, streamID)
	f.writeUint32(incr)
	return f.endWrite()
}

type http2HeadersFrame struct {
	http2FrameHeader
	Priority      http2PriorityParam
	headerFragBuf []byte
}

func (f *http2HeadersFrame) HeaderBlockFragment() []byte {
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

type http2HeadersFrameParam struct {
	StreamID      uint32
	BlockFragment []byte
	EndStream     bool
	EndHeaders    bool
	PadLength     uint8
	Priority      http2PriorityParam
}

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

type http2PriorityFrame struct {
	http2FrameHeader
	http2PriorityParam
}

type http2PriorityParam struct {
	StreamDep uint32

	Exclusive bool

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
	streamID := v & 0x7fffffff
	return &http2PriorityFrame{
		http2FrameHeader: fh,
		http2PriorityParam: http2PriorityParam{
			Weight:    payload[4],
			StreamDep: streamID,
			Exclusive: streamID != v,
		},
	}, nil
}

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

func (f *http2Framer) WriteRSTStream(streamID uint32, code errHttp2Code) error {
	f.startWrite(http2FrameRSTStream, 0, streamID)
	f.writeUint32(uint32(code))
	return f.endWrite()
}

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
	return f.headerFragBuf
}

func (f *http2ContinuationFrame) HeadersEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagContinuationEndHeaders)
}

func (f *http2Framer) WriteContinuation(streamID uint32, endHeaders bool, headerBlockFragment []byte) error {
	var flags http2Flags
	if endHeaders {
		flags |= http2FlagContinuationEndHeaders
	}
	f.startWrite(http2FrameContinuation, flags, streamID)
	f.wbuf = append(f.wbuf, headerBlockFragment...)
	return f.endWrite()
}

type http2PushPromiseFrame struct {
	http2FrameHeader
	PromiseID     uint32
	headerFragBuf []byte
}

func (f *http2PushPromiseFrame) HeaderBlockFragment() []byte {
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

		countError("frame_pushpromise_zero_stream")
		return nil, http2ConnectionError(errHttp2CodeProtocol)
	}

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

		countError("frame_pushpromise_pad_too_big")
		return nil, http2ConnectionError(errHttp2CodeProtocol)
	}
	pp.headerFragBuf = p[:len(p)-int(padLength)]
	return pp, nil
}

type http2PushPromiseParam struct {
	StreamID uint32

	PromiseID uint32

	BlockFragment []byte

	EndHeaders bool

	PadLength uint8
}

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

type http2MetaHeadersFrame struct {
	*http2HeadersFrame

	Fields []hpack.HeaderField
}

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

func (mh *http2MetaHeadersFrame) RegularFields() []hpack.HeaderField {
	for i, hf := range mh.Fields {
		if !hf.IsPseudo() {
			return mh.Fields[i:]
		}
	}
	return nil
}

func (mh *http2MetaHeadersFrame) PseudoFields() []hpack.HeaderField {
	for i, hf := range mh.Fields {
		if !hf.IsPseudo() {
			return mh.Fields[:i]
		}
	}
	return mh.Fields
}

func (fr *http2Framer) readMetaFrame(hf *http2HeadersFrame) (http2Frame, error) {
	mh := &http2MetaHeadersFrame{
		http2HeadersFrame: hf,
	}

	hdec := fr.ReadMetaHeaders
	hdec.SetEmitEnabled(true)
	hdec.SetEmitFunc(func(hf hpack.HeaderField) {
		mh.Fields = append(mh.Fields, hf)
	})

	defer hdec.SetEmitFunc(func(hf hpack.HeaderField) {})

	var hc http2headersOrContinuation = hf
	for {
		frag := hc.HeaderBlockFragment()
		if _, err := hdec.Write(frag); err != nil {
			return mh, http2ConnectionError(errHttp2CodeCompression)
		}
		if hc.HeadersEnded() {
			break
		}
		if f, err := fr.ReadFrame(); err != nil {
			return nil, err
		} else {
			hc = f.(*http2ContinuationFrame)
		}
	}

	mh.http2HeadersFrame.headerFragBuf = nil
	if err := hdec.Close(); err != nil {
		return mh, http2ConnectionError(errHttp2CodeCompression)
	}
	return mh, nil
}

var (
	http2commonBuildOnce   sync.Once
	http2commonLowerHeader map[string]string
	http2commonCanonHeader map[string]string
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
	http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
)

var (
	http2clientPreface = []byte(http2ClientPreface)
)

type http2Setting struct {
	ID http2SettingID

	Val uint32
}

func (s http2Setting) String() string {
	return fmt.Sprintf("[%v = %d]", s.ID, s.Val)
}

func (s http2Setting) Valid() error {

	switch s.ID {
	case Http2SettingEnablePush:
		if s.Val != 1 && s.Val != 0 {
			return http2ConnectionError(errHttp2CodeProtocol)
		}
	case Http2SettingInitialWindowSize:
		if s.Val > 1<<31-1 {
			return http2ConnectionError(errHttp2CodeFlowControl)
		}
	case Http2SettingMaxFrameSize:
		if s.Val < 16384 || s.Val > 1<<24-1 {
			return http2ConnectionError(errHttp2CodeProtocol)
		}
	}
	return nil
}

type http2SettingID uint16

const (
	Http2SettingHeaderTableSize      http2SettingID = 0x1
	Http2SettingEnablePush           http2SettingID = 0x2
	Http2SettingMaxConcurrentStreams http2SettingID = 0x3
	Http2SettingInitialWindowSize    http2SettingID = 0x4
	Http2SettingMaxFrameSize         http2SettingID = 0x5
	Http2SettingMaxHeaderListSize    http2SettingID = 0x6
)

var http2settingName = map[http2SettingID]string{
	Http2SettingHeaderTableSize:      "HEADER_TABLE_SIZE",
	Http2SettingEnablePush:           "ENABLE_PUSH",
	Http2SettingMaxConcurrentStreams: "MAX_CONCURRENT_STREAMS",
	Http2SettingInitialWindowSize:    "INITIAL_WINDOW_SIZE",
	Http2SettingMaxFrameSize:         "MAX_FRAME_SIZE",
	Http2SettingMaxHeaderListSize:    "MAX_HEADER_LIST_SIZE",
}

func (s http2SettingID) String() string {
	if v, ok := http2settingName[s]; ok {
		return v
	}
	return fmt.Sprintf("UNKNOWN_SETTING_%d", uint16(s))
}

func http2validPseudoPath(v string) bool {
	return (len(v) > 0 && v[0] == '/') || v == "*"
}

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

type Http2ClientConn struct {
	closeFunc         func()
	spec              gospiderOption
	loop              *http2clientConnReadLoop
	http2clientStream *http2clientStream

	err    error
	tconn  net.Conn
	inflow http2inflow

	nextStreamID      uint32
	maxFrameSize      uint32
	initialWindowSize uint32

	bw *bufio.Writer
	fr *http2Framer

	hbuf bytes.Buffer
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
	reqBodyContentLength int64
}

func (cc *Http2ClientConn) run() (err error) {
	defer func() {
		cc.err = err
		cc.CloseWithError(err)
	}()
	var f http2Frame
	for {
		if f, err = cc.fr.ReadFrame(); err != nil {
			return tools.WrapError(err, "ReadFrame")
		}
		switch f := f.(type) {
		case *http2MetaHeadersFrame:
			if cc.http2clientStream == nil {
				return tools.WrapError(errors.New("unexpected meta headers frame"), "run")
			}
			if cc.http2clientStream.resp, err = cc.loop.handleResponse(cc.http2clientStream, f); err != nil {
				return tools.WrapError(err, "handleResponse")
			}
			cc.http2clientStream.headCnl()
		case *http2DataFrame:
			if err = cc.loop.processData(cc.http2clientStream, f); err != nil {
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
	initialWindowSize uint32
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
func spec2option(h2Spec ja3.H2Spec) gospiderOption {
	var headerTableSize uint32 = 65536
	var maxHeaderListSize uint32 = 262144
	var initialWindowSize uint32 = 6291456

	if h2Spec.InitialSetting != nil {
		for _, setting := range h2Spec.InitialSetting {
			switch setting.Id {
			case ja3.Http2SettingHeaderTableSize:
				headerTableSize = setting.Val
			case ja3.Http2SettingMaxHeaderListSize:
				maxHeaderListSize = setting.Val
			case ja3.Http2SettingInitialWindowSize:
				initialWindowSize = setting.Val
			}
		}
	} else {
		h2Spec.InitialSetting = []ja3.Setting{
			{Id: ja3.Http2SettingHeaderTableSize, Val: headerTableSize},
			{Id: ja3.Http2SettingEnablePush, Val: 0},
			{Id: ja3.Http2SettingMaxConcurrentStreams, Val: 1000},
			{Id: ja3.Http2SettingInitialWindowSize, Val: initialWindowSize},
			{Id: ja3.Http2SettingMaxHeaderListSize, Val: maxHeaderListSize},
		}
	}
	if !h2Spec.Priority.Exclusive && h2Spec.Priority.StreamDep == 0 && h2Spec.Priority.Weight == 0 {
		h2Spec.Priority = ja3.Priority{
			Exclusive: true,
			StreamDep: 0,
			Weight:    255,
		}
	}
	if h2Spec.ConnFlow == 0 {
		h2Spec.ConnFlow = 15663105
	}
	h2Spec.OrderHeaders = clearOrderHeaders(h2Spec.OrderHeaders)
	return gospiderOption{
		orderHeaders:      h2Spec.OrderHeaders,
		initialSetting:    h2Spec.InitialSetting,
		priority:          h2Spec.Priority,
		initialWindowSize: initialWindowSize,
		connFlow:          h2Spec.ConnFlow,
		headerTableSize:   headerTableSize,
		maxHeaderListSize: maxHeaderListSize,
	}
}
func NewClientConn(ctx context.Context, c net.Conn, h2Spec ja3.H2Spec, closefun func()) (*Http2ClientConn, error) {
	spec := spec2option(h2Spec)
	cc := &Http2ClientConn{
		closeFunc:         closefun,
		spec:              spec,
		tconn:             c,
		nextStreamID:      1,
		maxFrameSize:      16 << 10,
		initialWindowSize: spec.initialWindowSize,
	}
	cc.bw = bufio.NewWriter(c)
	cc.fr = http2NewFramer(cc.bw, bufio.NewReader(c))
	cc.fr.ReadMetaHeaders = hpack.NewDecoder(cc.spec.headerTableSize, nil)
	cc.henc = hpack.NewEncoder(&cc.hbuf)
	cc.henc.SetMaxDynamicTableSizeLimit(cc.spec.headerTableSize)
	initialSettings := make([]http2Setting, len(cc.spec.initialSetting))
	for i, setting := range cc.spec.initialSetting {
		initialSettings[i] = http2Setting{ID: http2SettingID(setting.Id), Val: setting.Val}
	}
	done := make(chan struct{})
	var err error
	go func() {
		defer close(done)
		if _, err = cc.bw.Write(http2clientPreface); err != nil {
			return
		}
		if err = cc.fr.WriteSettings(initialSettings...); err != nil {
			return
		}
		if err = cc.fr.WriteWindowUpdate(0, cc.spec.connFlow); err != nil {
			return
		}
		cc.inflow.initConn(int32(cc.spec.connFlow))
		if err = cc.bw.Flush(); err != nil {
			return
		}
	}()
	select {
	case <-done:
		if err != nil {
			return nil, err
		}
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
	cc.loop = &http2clientConnReadLoop{cc: cc}
	go cc.run()
	return cc, nil
}

func (cc *Http2ClientConn) CloseWithError(err error) error {
	if err != io.EOF && cc.closeFunc != nil {
		cc.closeFunc()
	}
	cc.tconn.Close()
	if cc.http2clientStream != nil {
		cc.http2clientStream.headCnl()
		cc.http2clientStream.bodyReader.CloseWithError(err)
		cc.http2clientStream.bodyWriter.CloseWithError(err)
	}
	return nil
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
		reqBodyContentLength: http2actualContentLength(req),
		bodyReader:           reader,
		bodyWriter:           writer,
	}
	cc.http2clientStream = cs
	err := cs.writeRequest(req, orderHeaders)
	if err != nil {
		return nil, err
	}
	if req.Body != nil {
		defer req.Body.Close()
	}
	select {
	case <-cs.headCtx.Done():
		if cs.resp != nil {
			cs.resp.Request = req
		}
		return cs.resp, cc.err
	case <-ctx.Done():
		if cc.err != nil {
			return nil, cc.err
		}
		return nil, ctx.Err()
	}
}

func (cs *http2clientStream) writeRequest(req *http.Request, orderHeaders []string) (err error) {
	cs.cc.inflow.initStream(int32(cs.cc.initialWindowSize))
	cs.ID = cs.cc.nextStreamID
	cs.cc.nextStreamID += 2

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

	endStream := !hasBody && !hasTrailers
	err = cc.writeHeaders(cs.ID, endStream, int(cc.maxFrameSize), hdrs)
	return err
}

func (cc *Http2ClientConn) writeHeaders(streamID uint32, endStream bool, maxFrameSize int, hdrs []byte) error {
	first := true
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
	return int(n)
}

func (cs *http2clientStream) writeRequestBody(req *http.Request) (err error) {
	sentEnd := false
	var sawEOF bool
	buf := make([]byte, cs.frameScratchBufferLen(int(cs.cc.maxFrameSize)))
	for !sawEOF {
		n, err := req.Body.Read(buf)
		if err != nil {
			if err == io.EOF {
				sawEOF = true
				err = nil
			} else {
				return err
			}
		}
		if n > 0 {
			sentEnd = sawEOF && req.Trailer == nil
			err = cs.cc.fr.WriteData(cs.ID, sentEnd, buf[:n])
			if err == nil {
				err = cs.cc.bw.Flush()
			}
		}
		if err != nil {
			return err
		}
	}
	if sentEnd {
		return nil
	}
	var trls []byte
	if len(req.Trailer) > 0 {
		trls, err = cs.cc.encodeTrailers(req.Trailer)
		if err != nil {
			return err
		}
	}
	if len(trls) > 0 {
		err = cs.cc.writeHeaders(cs.ID, true, int(cs.cc.maxFrameSize), trls)
	} else {
		err = cs.cc.fr.WriteData(cs.ID, true, nil)
	}
	if err != nil {
		return err
	}
	return cs.cc.bw.Flush()
}

func (cc *Http2ClientConn) encodeHeaders(req *http.Request, trailers string, contentLength int64, orderHeaders []string) ([]byte, error) {
	cc.hbuf.Reset()
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	host, err := httpguts.PunycodeHostPort(host)
	if err != nil {
		return nil, err
	}
	var path string
	if req.Method != "CONNECT" {
		path = req.URL.RequestURI()
		if !http2validPseudoPath(path) {
			path = strings.TrimPrefix(path, req.URL.Scheme+"://"+host)
		}
	}
	enumerateHeaders := func(replaceF func(name, value string)) {
		gospiderHeaders := map[string][]string{}
		f := func(name, value string) {
			name = strings.ToLower(name)
			gospiderHeaders[name] = append(gospiderHeaders[name], value)
		}

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

				for _, v := range vv {
					for {
						p := strings.IndexByte(v, ';')
						if p < 0 {
							break
						}
						f("cookie", v[:p])
						p++

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

	hlSize := uint64(0)
	enumerateHeaders(func(name, value string) {
		hf := hpack.HeaderField{Name: name, Value: value}
		hlSize += uint64(hf.Size())
	})

	enumerateHeaders(func(name, value string) {
		name, ascii := http2lowerHeader(name)
		if !ascii {

			return
		}
		cc.writeHeader(name, value)
	})

	return cc.hbuf.Bytes(), nil
}

func http2shouldSendReqContentLength(method string, contentLength int64) bool {
	if contentLength > 0 {
		return true
	}
	if contentLength < 0 {
		return false
	}

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

type http2clientConnReadLoop struct {
	cc *Http2ClientConn
}

func (rl *http2clientConnReadLoop) handleResponse(cs *http2clientStream, f *http2MetaHeadersFrame) (*http.Response, error) {
	status := f.PseudoValue("status")
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
		return res, nil
	}
	res.Body = http2transportResponseBody{cs}
	return res, nil
}

type http2transportResponseBody struct {
	cs *http2clientStream
}

func (b http2transportResponseBody) Read(p []byte) (n int, err error) {
	return b.cs.bodyReader.Read(p)
}
func (b http2transportResponseBody) Close() error {
	return b.cs.bodyReader.Close()
}
func (rl *http2clientConnReadLoop) processData(cs *http2clientStream, f *http2DataFrame) error {
	data := f.Data()
	if f.Length > 0 {
		if len(data) > 0 {
			if _, err := cs.bodyWriter.Write(data); err != nil {
				return err
			}
		}
		connAdd, streamAdd := rl.cc.inflow.add(int32(f.Length), int32(len(data)))
		if connAdd > 0 {
			rl.cc.fr.WriteWindowUpdate(0, uint32(connAdd))
			rl.cc.bw.Flush()
		}
		if streamAdd > 0 {
			rl.cc.fr.WriteWindowUpdate(cs.ID, uint32(streamAdd))
			rl.cc.bw.Flush()
		}
	}
	if f.StreamEnded() {
		cs.bodyWriter.CloseWithError(io.EOF)
	}
	return nil
}
func (rl *http2clientConnReadLoop) processGoAway(f *http2GoAwayFrame) error {
	if f.ErrCode == 0 {
		return nil
	}
	return fmt.Errorf("http2: server sent GOAWAY with error code %v", f.ErrCode)
}
func (rl *http2clientConnReadLoop) processSettings(f *http2SettingsFrame) error {
	if err := rl.processSettingsNoWrite(f); err != nil {
		return err
	}
	if !f.IsAck() {
		rl.cc.fr.WriteSettingsAck()
		rl.cc.bw.Flush()
	}
	return nil
}
func (rl *http2clientConnReadLoop) processSettingsNoWrite(f *http2SettingsFrame) error {
	err := f.ForeachSetting(func(s http2Setting) error {
		switch s.ID {
		case Http2SettingMaxFrameSize:
			rl.cc.maxFrameSize = s.Val
		case Http2SettingMaxHeaderListSize:
		case Http2SettingInitialWindowSize:
			rl.cc.initialWindowSize = s.Val
		case Http2SettingHeaderTableSize:
			rl.cc.henc.SetMaxDynamicTableSize(s.Val)
		default:
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (rl *http2clientConnReadLoop) processResetStream(f *http2RSTStreamFrame) error {
	if f.ErrCode == 0 {
		return nil
	}
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
