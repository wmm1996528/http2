package http2

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gospider007/tools"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2/hpack"
)

type Http2ClientConn struct {
	tconn             net.Conn
	closeFunc         func(error)
	loop              *http2clientConnReadLoop
	http2clientStream *http2clientStream

	wmu sync.Mutex

	bw *bufio.Writer
	fr *http2Framer

	henc *hpack.Encoder
	hbuf bytes.Buffer

	spec   gospiderOption
	inflow http2inflow
	flow   http2outflow

	streamID uint32

	flowNotices chan struct{}
	ctx         context.Context
	cnl         context.CancelCauseFunc
	shutdownErr error
}

func (obj *Http2ClientConn) Stream() io.ReadWriteCloser {
	return nil
}

type respC struct {
	resp *http.Response
	err  error
}

type http2clientStream struct {
	cc *Http2ClientConn

	bodyReader *io.PipeReader
	bodyWriter *io.PipeWriter
	ID         uint32
	inflow     http2inflow
	flow       http2outflow

	respDone chan *respC

	writeCtx context.Context
	writeCnl context.CancelFunc

	readCtx context.Context
	readCnl context.CancelCauseFunc
}

func (cc *Http2ClientConn) notice() {
	select {
	case cc.flowNotices <- struct{}{}:
	default:
	}
}

func (cc *Http2ClientConn) run() (err error) {
	defer func() {
		cc.CloseWithError(err)
	}()
	for {
		f, err := cc.fr.ReadFrame()
		if err != nil {
			return tools.WrapError(err, "ReadFrame")
		}
		switch f := f.(type) {
		case *Http2MetaHeadersFrame:
			if cc.http2clientStream == nil {
				return tools.WrapError(errors.New("unexpected meta headers frame"), "run")
			}
			resp, err := cc.loop.handleResponse(cc.http2clientStream, f)
			select {
			case cc.http2clientStream.respDone <- &respC{resp: resp, err: err}:
			case <-cc.ctx.Done():
				err = cc.ctx.Err()
			}
			if err != nil {
				return tools.WrapError(err, "handleResponse")
			}
		case *Http2DataFrame:
			if err = cc.loop.processData(cc.http2clientStream, f); err != nil {
				return tools.WrapError(err, "processData")
			}
		case *Http2GoAwayFrame:
			if f.ErrCode == 0 {
				cc.shutdownErr = fmt.Errorf("http2: server sent GOAWAY with close connection ok")
			} else {
				err = fmt.Errorf("http2: server sent GOAWAY with error code %v", f.ErrCode)
				return tools.WrapError(err, "GOAWAY")
			}
		case *Http2RSTStreamFrame:
			if f.ErrCode == 0 {
				cc.shutdownErr = fmt.Errorf("http2: server sent processResetStream with close connection ok")
			} else {
				err = fmt.Errorf("http2: server sent processResetStream with error code %v", f.ErrCode)
				return tools.WrapError(err, "processResetStream")
			}
		case *Http2SettingsFrame:
			if err = cc.loop.processSettings(f); err != nil {
				return tools.WrapError(err, "processSettings")
			}
		case *Http2PushPromiseFrame:
		case *Http2WindowUpdateFrame:
			if err = cc.loop.processWindowUpdate(f); err != nil {
				return tools.WrapError(err, "processWindowUpdate")
			}
		case *Http2PingFrame:
			if err = cc.loop.processPing(f); err != nil {
				return tools.WrapError(err, "processPing")
			}
		default:
			err = fmt.Errorf("unknown frame type: %T", f)
			return tools.WrapError(err, "run")
		}
		if cc.shutdownErr != nil {
			if cc.http2clientStream != nil {
				select {
				case <-cc.http2clientStream.readCtx.Done():
					return cc.shutdownErr
				default:
				}
			} else {
				return cc.shutdownErr
			}
		}
	}
}

type gospiderOption struct {
	initialSetting    []Http2Setting
	priority          Http2PriorityParam
	connFlow          uint32
	initialWindowSize uint32
	headerTableSize   uint32
	maxHeaderListSize uint32
	maxFrameSize      uint32
}

func spec2option(h2Spec *Spec) (option gospiderOption) {
	if h2Spec == nil {
		//golang setting: start
		option.initialWindowSize = 4194304
		option.maxFrameSize = 16384
		option.maxHeaderListSize = 10485760
		option.initialSetting = []Http2Setting{
			{ID: 2, Val: 0},
			{ID: 4, Val: option.initialWindowSize},
			{ID: 5, Val: option.maxFrameSize},
			{ID: 6, Val: option.maxHeaderListSize},
		}
		option.priority = Http2PriorityParam{}
		option.connFlow = 1073741824
		option.headerTableSize = 4096
		h2Spec = nil
		//golang setting: end
	} else {
		option.initialSetting = h2Spec.Settings
		option.priority = h2Spec.Priority
		option.headerTableSize = 65536
		option.maxHeaderListSize = 262144
		option.initialWindowSize = 6291456
		option.maxFrameSize = 16384
		if h2Spec.ConnFlow > 0 {
			option.connFlow = h2Spec.ConnFlow
		} else {
			option.connFlow = 15663105
		}
	}
	for _, setting := range option.initialSetting {
		switch setting.ID {
		case Http2SettingHeaderTableSize:
			option.headerTableSize = setting.Val
		case Http2SettingMaxHeaderListSize:
			option.maxHeaderListSize = setting.Val
		case Http2SettingInitialWindowSize:
			option.initialWindowSize = setting.Val
		case Http2SettingMaxFrameSize:
			option.maxFrameSize = setting.Val
		}
	}
	return option
}

func NewClientConn(ctx context.Context, c net.Conn, h2Spec *Spec, closefun func(error)) (*Http2ClientConn, error) {
	var streamID uint32
	if h2Spec != nil {
		streamID = h2Spec.StreamID
	} else {
		streamID = 1
	}
	spec := spec2option(h2Spec)
	cc := &Http2ClientConn{
		closeFunc:   closefun,
		spec:        spec,
		tconn:       c,
		flowNotices: make(chan struct{}, 1),
		streamID:    streamID,
	}
	cc.ctx, cc.cnl = context.WithCancelCause(context.TODO())
	cc.bw = bufio.NewWriter(c)
	cc.fr = http2NewFramer(cc.bw, bufio.NewReader(c))
	cc.fr.ReadMetaHeaders = hpack.NewDecoder(cc.spec.headerTableSize, nil)
	cc.henc = hpack.NewEncoder(&cc.hbuf)
	cc.henc.SetMaxDynamicTableSizeLimit(cc.spec.headerTableSize)
	cc.spec.initialWindowSize = 65535
	cc.flow.add(int32(cc.spec.initialWindowSize))
	done := make(chan struct{})
	var err error
	go func() {
		defer close(done)
		if h2Spec != nil && len(h2Spec.initData) > 0 {
			rawData := []byte(fmt.Sprintf("%s\r\n\r\n%s\r\n\r\n", h2Spec.Pri, h2Spec.Sm))
			rawData = append(rawData, h2Spec.initData...)
			if _, err = cc.bw.Write(rawData); err != nil {
				return
			}
		} else {
			if _, err = cc.bw.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
				return
			}
			if err = cc.fr.WriteSettings(cc.spec.initialSetting...); err != nil {
				return
			}
			if err = cc.fr.WriteWindowUpdate(0, cc.spec.connFlow); err != nil {
				return
			}
		}
		cc.inflow.init(int32(cc.spec.connFlow) + int32(cc.spec.initialWindowSize))
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
	if cc.closeFunc != nil {
		cc.closeFunc(err)
	}
	cc.cnl(err)
	cc.tconn.Close()
	if cc.http2clientStream != nil {
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

func (cc *Http2ClientConn) initStream() {
	cc.wmu.Lock()
	defer cc.wmu.Unlock()
	reader, writer := io.Pipe()
	cs := &http2clientStream{
		cc:         cc,
		bodyReader: reader,
		bodyWriter: writer,
		respDone:   make(chan *respC),
	}
	cs.writeCtx, cs.writeCnl = context.WithCancel(cc.ctx)
	cs.readCtx, cs.readCnl = context.WithCancelCause(cc.ctx)
	cc.http2clientStream = cs
	cs.inflow.init(int32(cc.spec.initialWindowSize))
	cs.flow.add(int32(cc.spec.initialWindowSize))
	cs.flow.setConnFlow(&cc.flow)
	cs.ID = cc.streamID
	cc.streamID += 2
}

func (cc *Http2ClientConn) DoRequest(req *http.Request, orderHeaders []interface {
	Key() string
	Val() any
}) (response *http.Response, bodyCtx context.Context, err error) {
	defer func() {
		if err != nil {
			cc.CloseWithError(err)
		}
	}()
	if cc.shutdownErr != nil {
		return nil, nil, cc.shutdownErr
	}
	cc.initStream()
	go cc.http2clientStream.writeRequest(req, orderHeaders)
	select {
	case respData := <-cc.http2clientStream.respDone:
		return respData.resp, cc.http2clientStream.readCtx, respData.err
	case <-cc.ctx.Done():
		return nil, nil, cc.ctx.Err()
	case <-req.Context().Done():
		return nil, nil, req.Context().Err()
	}
}

func (cs *http2clientStream) writeRequest(req *http.Request, orderHeaders []interface {
	Key() string
	Val() any
}) (err error) {
	defer func() {
		if err != nil {
			cs.cc.CloseWithError(err)
		}
		cs.writeCnl()
	}()
	if err = cs.encodeAndWriteHeaders(req, orderHeaders); err != nil {
		return err
	}
	if http2actualContentLength(req) != 0 {
		return cs.writeRequestBody(req)
	}
	return
}

func (cs *http2clientStream) encodeAndWriteHeaders(req *http.Request, orderHeaders []interface {
	Key() string
	Val() any
}) error {
	cs.cc.wmu.Lock()
	defer cs.cc.wmu.Unlock()
	hdrs, err := cs.cc.encodeHeaders(req, orderHeaders)
	if err != nil {
		return err
	}
	return cs.cc.writeHeaders(cs.ID, http2actualContentLength(req) == 0, int(cs.cc.spec.maxFrameSize), hdrs)
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
			http2HeadersFrameParam := Http2HeadersFrameParam{
				StreamID:      streamID,
				BlockFragment: chunk,
				EndStream:     endStream,
				EndHeaders:    endHeaders,
			}
			if cc.spec.priority.StreamDep != 0 || cc.spec.priority.Weight != 0 || cc.spec.priority.Exclusive {
				http2HeadersFrameParam.Priority = Http2PriorityParam{
					StreamDep: cc.spec.priority.StreamDep,
					Exclusive: cc.spec.priority.Exclusive,
					Weight:    cc.spec.priority.Weight,
				}
			}
			if err := cc.fr.WriteHeaders(http2HeadersFrameParam); err != nil {
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

func (cs *http2clientStream) frameScratchBufferLen(req *http.Request, maxFrameSize int) int {
	const max = 512 << 10
	n := int64(maxFrameSize)
	if n > max {
		n = max
	}
	if cl := http2actualContentLength(req); cl != -1 && cl+1 < n {
		n = cl + 1
	}
	if n < 1 {
		return 1
	}
	return int(n)
}

func (cs *http2clientStream) available(maxBytes int) (taken int32) {
	cs.cc.wmu.Lock()
	defer cs.cc.wmu.Unlock()
	if a := cs.flow.available(); a > 0 {
		take := a
		if int(take) > maxBytes {
			take = int32(maxBytes) // can't truncate int; take is int32
		}
		if take > int32(cs.cc.spec.maxFrameSize) {
			take = int32(cs.cc.spec.maxFrameSize)
		}
		cs.flow.take(take)
		return take
	}
	return 0
}
func (cs *http2clientStream) awaitFlowControl(maxBytes int) (taken int32, err error) {
	for {
		if taken = cs.available(maxBytes); taken > 0 {
			return
		}
		select {
		case <-cs.cc.ctx.Done():
			return 0, context.Cause(cs.cc.ctx)
		case <-cs.readCtx.Done():
			return 0, context.Cause(cs.readCtx)
		case <-cs.cc.flowNotices:
		case <-time.After(time.Second * 30):
			return 0, errors.New("timeout waiting for flow control")
		}
	}
}

func (cs *http2clientStream) writeRequestBody(req *http.Request) (bodyErr error) {
	buf := make([]byte, cs.frameScratchBufferLen(req, int(cs.cc.spec.maxFrameSize)))
	for {
		n, err := req.Body.Read(buf)
		if n > 0 {
			if bodyErr = cs.WriteData(err != nil, buf[:n]); bodyErr != nil {
				return
			}
		} else if err != nil {
			if bodyErr = cs.WriteEndNoData(); bodyErr != nil {
				return
			}
		}
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return
			}
			bodyErr = err
			return
		}
	}
}

func (cs *http2clientStream) WriteEndNoData() (err error) {
	cs.cc.wmu.Lock()
	defer cs.cc.wmu.Unlock()
	err = cs.cc.fr.WriteData(cs.ID, true, nil)
	if err == nil {
		err = cs.cc.bw.Flush()
	}
	return err
}

func (cs *http2clientStream) WriteData(endStream bool, remain []byte) (err error) {
	if endStream && len(remain) == 0 {
		return cs.WriteEndNoData()
	}
	for len(remain) > 0 && err == nil {
		var allowed int32
		allowed, err = cs.awaitFlowControl(len(remain))
		if err != nil {
			return err
		}
		data := remain[:allowed]
		remain = remain[allowed:]
		sentEnd := endStream && len(remain) == 0
		cs.cc.wmu.Lock()
		err = cs.cc.fr.WriteData(cs.ID, sentEnd, data)
		if err == nil {
			err = cs.cc.bw.Flush()
		}
		cs.cc.wmu.Unlock()
	}
	return
}

func (cc *Http2ClientConn) encodeHeaders(req *http.Request, orderHeaders []interface {
	Key() string
	Val() any
}) ([]byte, error) {
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
		gospiderHeaders := [][2]string{}
		f := func(name, value string) {
			gospiderHeaders = append(gospiderHeaders, [2]string{
				strings.ToLower(name), value,
			})
		}
		f(":method", req.Method)
		f(":authority", host)
		if req.Method != http.MethodConnect {
			f(":scheme", req.URL.Scheme)
			f(":path", path)
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

		if contentLength, _ := tools.GetContentLength(req); contentLength >= 0 {
			f("content-length", strconv.FormatInt(contentLength, 10))
		}
		for _, kv := range tools.NewHeadersWithH2(orderHeaders, gospiderHeaders) {
			replaceF(kv[0], kv[1])
		}
	}
	enumerateHeaders(func(name, value string) {
		name = strings.ToLower(name)
		fmt.Printf(name, value)
		cc.writeHeader(name, value)
	})
	return cc.hbuf.Bytes(), nil
}

func (cc *Http2ClientConn) writeHeader(name, value string) {
	cc.henc.WriteField(hpack.HeaderField{Name: name, Value: value})
}

type http2clientConnReadLoop struct {
	cc *Http2ClientConn
}

type http2noBodyReader struct{}

func (http2noBodyReader) Close() error { return nil }

func (http2noBodyReader) Read([]byte) (int, error) { return 0, io.EOF }

func (rl *http2clientConnReadLoop) handleResponse(cs *http2clientStream, f *Http2MetaHeadersFrame) (*http.Response, error) {
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
		res.Body = http2noBodyReader{}
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
func (rl *http2clientConnReadLoop) processData(cs *http2clientStream, f *Http2DataFrame) (err error) {
	if f.Length > 0 {
		if len(f.Data()) > 0 {
			if _, err = cs.bodyWriter.Write(f.Data()); err != nil {
				return err
			}
		}
		cs.cc.wmu.Lock()
		defer cs.cc.wmu.Unlock()
		connAdd := rl.cc.inflow.add(int32(f.Length))
		streamAdd := cs.inflow.add(int32(f.Length))
		if connAdd > 0 || streamAdd > 0 {
			if connAdd > 0 {
				if err = rl.cc.fr.WriteWindowUpdate(0, uint32(connAdd)); err != nil {
					return err
				}
			}
			if streamAdd > 0 {
				if err = rl.cc.fr.WriteWindowUpdate(cs.ID, uint32(connAdd)); err != nil {
					return err
				}
			}
			if err = rl.cc.bw.Flush(); err != nil {
				return err
			}
		}
	}
	if f.StreamEnded() {
		select {
		case <-cs.writeCtx.Done():
		default:
			err = errors.New("last task not write done with read done")
		}
		cs.readCnl(err)
		cs.bodyWriter.CloseWithError(io.EOF)
	}
	return
}

func (rl *http2clientConnReadLoop) processWindowUpdate(f *Http2WindowUpdateFrame) error {
	rl.cc.wmu.Lock()
	defer rl.cc.wmu.Unlock()
	if f.StreamID == 0 {
		rl.cc.flow.add(int32(f.Increment))
	} else {
		rl.cc.http2clientStream.flow.add(int32(f.Increment))
	}
	rl.cc.notice()
	return nil
}
func (rl *http2clientConnReadLoop) processSettings(f *Http2SettingsFrame) error {
	rl.cc.wmu.Lock()
	defer rl.cc.wmu.Unlock()
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
func (rl *http2clientConnReadLoop) processSettingsNoWrite(f *Http2SettingsFrame) error {
	return f.ForeachSetting(func(s Http2Setting) error {
		switch s.ID {
		case Http2SettingMaxFrameSize:
			rl.cc.spec.maxFrameSize = s.Val
		case Http2SettingInitialWindowSize:
			if rl.cc.http2clientStream != nil {
				rl.cc.http2clientStream.flow.n = int32(s.Val)
				rl.cc.notice()
			}
			rl.cc.spec.initialWindowSize = s.Val
		case Http2SettingHeaderTableSize:
			rl.cc.henc.SetMaxDynamicTableSize(s.Val)
			rl.cc.fr.ReadMetaHeaders.SetMaxDynamicTableSize(s.Val)
		default:
		}
		return nil
	})
}

func (rl *http2clientConnReadLoop) processPing(f *Http2PingFrame) error {
	rl.cc.wmu.Lock()
	defer rl.cc.wmu.Unlock()
	if err := rl.cc.fr.WritePing(true, f.Data); err != nil {
		return err
	}
	return rl.cc.bw.Flush()
}
