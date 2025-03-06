package http2

import (
	"io"

	"golang.org/x/net/http2/hpack"
)

type Http2ReaderFramer struct {
	r               io.Reader
	getReadBuf      func(size uint32) []byte
	ReadMetaHeaders *hpack.Decoder
	frameCache      *http2frameCache
	readBuf         []byte
	headerBuf       [http2frameHeaderLen]byte
}

func Http2NewReaderFramer(r io.Reader) *Http2ReaderFramer {
	fr := &Http2ReaderFramer{
		r:               r,
		ReadMetaHeaders: hpack.NewDecoder(65536, nil),
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

func (fr *Http2ReaderFramer) ReadRawFrame() (any, []byte, error) {
	fh, err := http2readFrameHeader(fr.headerBuf[:], fr.r)
	if err != nil {
		return nil, nil, err
	}
	payload := fr.getReadBuf(fh.Length)
	if _, err := io.ReadFull(fr.r, payload); err != nil {
		return nil, nil, err
	}
	data := fr.headerBuf[:http2frameHeaderLen]
	data = append(data, payload...)
	v, err := http2typeFrameParser(fh.Type)(fr.frameCache, fh, payload)
	return v, data, err
}

func (fr *Http2ReaderFramer) ReadFrame() (any, error) {
	fh, err := http2readFrameHeader(fr.headerBuf[:], fr.r)
	if err != nil {
		return nil, err
	}
	payload := fr.getReadBuf(fh.Length)
	if _, err := io.ReadFull(fr.r, payload); err != nil {
		return nil, err
	}
	f, err := http2typeFrameParser(fh.Type)(fr.frameCache, fh, payload)
	if err != nil {
		return nil, err
	}
	if setting, ok := f.(*Http2SettingsFrame); ok {
		setting.ForeachSetting(
			func(hs Http2Setting) error {
				if hs.ID == Http2SettingHeaderTableSize {
					fr.ReadMetaHeaders.SetMaxDynamicTableSize(hs.Val)
				}
				return nil
			},
		)
	}
	if fh.Type == http2FrameHeaders {
		return fr.readMetaFrame(f.(*Http2HeadersFrame))
	}
	return f, nil
}
func (fr *Http2ReaderFramer) readMetaFrame(hf *Http2HeadersFrame) (any, error) {
	mh := &Http2MetaHeadersFrame{
		Http2HeadersFrame: hf,
	}
	fr.ReadMetaHeaders.SetEmitEnabled(true)
	fr.ReadMetaHeaders.SetEmitFunc(func(hf hpack.HeaderField) {
		mh.Fields = append(mh.Fields, hf)
	})
	defer func() {
		fr.ReadMetaHeaders.SetEmitEnabled(false)
		fr.ReadMetaHeaders.SetEmitFunc(nil)
	}()
	var hc http2headersOrContinuation = hf
	for {
		frag := hc.HeaderBlockFragment()
		if _, err := fr.ReadMetaHeaders.Write(frag); err != nil {
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
	mh.Http2HeadersFrame.headerFragBuf = nil
	if err := fr.ReadMetaHeaders.Close(); err != nil {
		return mh, http2ConnectionError(errHttp2CodeCompression)
	}
	return mh, nil
}
