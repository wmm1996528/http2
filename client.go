package http2

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"slices"
	"strconv"
	"strings"

	"github.com/gospider007/ja3"
	"github.com/gospider007/tools"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2/hpack"
)

type Http2ClientConn struct {
	err               error
	tconn             net.Conn
	closeFunc         func()
	loop              *http2clientConnReadLoop
	http2clientStream *http2clientStream

	bw *bufio.Writer
	fr *http2Framer

	henc *hpack.Encoder

	hbuf   bytes.Buffer
	spec   gospiderOption
	inflow http2inflow

	nextStreamID      uint32
	maxFrameSize      uint32
	initialWindowSize uint32
}

type http2clientStream struct {
	ctx                  context.Context
	headCtx              context.Context
	cc                   *Http2ClientConn
	headCnl              context.CancelFunc
	resp                 *http.Response
	bodyReader           *io.PipeReader
	bodyWriter           *io.PipeWriter
	reqBodyContentLength int64
	ID                   uint32
}

func (cc *Http2ClientConn) run() (err error) {
	defer func() {
		cc.err = err
		cc.CloseWithError(err)
	}()
	for {
		f, err := cc.fr.ReadFrame()
		if err != nil {
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
			if f.ErrCode == 0 {
				err = fmt.Errorf("http2: server sent GOAWAY with close connection ok")
			} else {
				err = fmt.Errorf("http2: server sent GOAWAY with error code %v", f.ErrCode)
			}
			return tools.WrapError(err, "processGoAway")
		case *http2RSTStreamFrame:
			if f.ErrCode == 0 {
				err = fmt.Errorf("http2: server sent processResetStream with close connection ok")
			} else {
				err = fmt.Errorf("http2: server sent processResetStream with error code %v", f.ErrCode)
			}
			return tools.WrapError(err, "processResetStream")
		case *http2SettingsFrame:
			if err = cc.loop.processSettings(f); err != nil {
				return tools.WrapError(err, "processSettings")
			}
		case *http2PushPromiseFrame:
			err = http2ConnectionError(errHttp2CodeProtocol)
			return tools.WrapError(err, "processPushPromise")
		case *http2WindowUpdateFrame:
		case *http2PingFrame:
			if err = cc.loop.processPing(f); err != nil {
				return tools.WrapError(err, "processPing")
			}
		default:
			return tools.WrapError(fmt.Errorf("unknown frame type: %T", f), "run")
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
func spec2option(h2Spec ja3.HSpec) gospiderOption {
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
func NewClientConn(ctx context.Context, c net.Conn, h2Spec ja3.HSpec, closefun func()) (*Http2ClientConn, error) {
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
		if _, err = cc.bw.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
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
	cs.cc.inflow.initRecv()
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
	hdrs, err := cc.encodeHeaders(req, orderHeaders)
	if err != nil {
		return err
	}
	return cc.writeHeaders(cs.ID, http2actualContentLength(req) == 0, int(cc.maxFrameSize), hdrs)
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
			if err := cc.fr.WriteHeaders(http2HeadersFrameParam{
				StreamID:      streamID,
				BlockFragment: chunk,
				EndStream:     endStream,
				EndHeaders:    endHeaders,
				Priority: http2PriorityParam{
					StreamDep: cc.spec.priority.StreamDep,
					Exclusive: cc.spec.priority.Exclusive,
					Weight:    cc.spec.priority.Weight,
				},
			}); err != nil {
				return err
			}
			first = false
		} else {
			if err := cc.fr.WriteContinuation(streamID, endHeaders, chunk); err != nil {
				return err
			}
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
	buf := make([]byte, cs.frameScratchBufferLen(int(cs.cc.maxFrameSize)))
	for {
		n, err := req.Body.Read(buf)
		if n > 0 {
			if writeErr := cs.cc.fr.WriteData(cs.ID, err != nil, buf[:n]); writeErr != nil {
				return writeErr
			}
			if writeErr := cs.cc.bw.Flush(); writeErr != nil {
				return writeErr
			}
		} else if err != nil {
			if writeErr := cs.cc.fr.WriteData(cs.ID, true, nil); writeErr != nil {
				return writeErr
			}
			if writeErr := cs.cc.bw.Flush(); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return err
		}
	}
}

func (cc *Http2ClientConn) encodeHeaders(req *http.Request, orderHeaders []string) ([]byte, error) {
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
	if req.Method != http.MethodConnect {
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
		f(":method", http.MethodGet)
		if req.Method != http.MethodConnect {
			f(":path", path)
			f(":scheme", req.URL.Scheme)
		}
		for k, vv := range req.Header {
			switch strings.ToLower(k) {
			case "host", "content-length", "connection", "proxy-connection", "transfer-encoding", "upgrade", "keep-alive":
			case "cookie":
				for _, v := range vv {
					for _, c := range strings.Split(v, "; ") {
						f("cookie", c)
					}
				}
			default:
				for _, v := range vv {
					f(k, v)
				}
			}
		}
		if contentLength := http2actualContentLength(req); http2shouldSendReqContentLength(req.Method, contentLength) {
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
		name = strings.ToLower(name)
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
	res := &http.Response{
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		Header:     make(http.Header),
		StatusCode: statusCode,
		Status:     status + " " + http.StatusText(statusCode),
	}
	for _, hf := range regularFields {
		key := http.CanonicalHeaderKey(hf.Name)
		if key == "Trailer" {
			if res.Trailer == nil {
				res.Trailer = make(http.Header)
			}
			for _, f := range strings.Split(hf.Value, ",") {
				if f = textproto.TrimString(f); f != "" {
					res.Trailer[http.CanonicalHeaderKey(f)] = nil
				}
			}
		} else {
			res.Header.Add(key, hf.Value)
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
	if f.Length > 0 {
		if len(f.Data()) > 0 {
			if _, err := cs.bodyWriter.Write(f.Data()); err != nil {
				return err
			}
		}
		if connAdd := rl.cc.inflow.add(int32(f.Length), int32(len(f.Data()))); connAdd > 0 {
			if err := rl.cc.fr.WriteWindowUpdate(0, uint32(connAdd)); err != nil {
				return err
			}
			if err := rl.cc.fr.WriteWindowUpdate(cs.ID, uint32(connAdd)); err != nil {
				return err
			}
			if err := rl.cc.bw.Flush(); err != nil {
				return err
			}
		}
	}
	if f.StreamEnded() {
		return cs.bodyWriter.CloseWithError(io.EOF)
	}
	return nil
}

func (rl *http2clientConnReadLoop) processSettings(f *http2SettingsFrame) error {
	if err := rl.processSettingsNoWrite(f); err != nil {
		return err
	}
	if !f.IsAck() {
		if err := rl.cc.fr.WriteSettingsAck(); err != nil {
			return err
		}
		return rl.cc.bw.Flush()
	}
	return nil
}
func (rl *http2clientConnReadLoop) processSettingsNoWrite(f *http2SettingsFrame) error {
	return f.ForeachSetting(func(s http2Setting) error {
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
}
func (cc *Http2ClientConn) Ping(ctx context.Context) error {
	var p [8]byte
	rand.Read(p[:])
	if pingError := cc.fr.WritePing(false, p); pingError != nil {
		return pingError
	}
	return cc.bw.Flush()
}
func (rl *http2clientConnReadLoop) processPing(f *http2PingFrame) error {
	if err := rl.cc.fr.WritePing(true, f.Data); err != nil {
		return err
	}
	return rl.cc.bw.Flush()
}
