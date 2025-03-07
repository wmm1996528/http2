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

func (fr *Http2ReaderFramer) ReadFrame() (any, []byte, error) {
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
	f, err := http2typeFrameParser(fh.Type)(fr.frameCache, fh, payload)
	if err != nil {
		return nil, nil, err
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
		f2, data2, err2 := fr.readMetaFrame(f.(*Http2HeadersFrame))
		if err2 != nil {
			return nil, nil, err2
		}
		data = append(data, data2...)
		return f2, data, nil
	}
	return f, data, nil
}
func (fr *Http2ReaderFramer) readMetaFrame(hf *Http2HeadersFrame) (any, []byte, error) {
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
	allData := []byte{}
	for {
		frag := hc.HeaderBlockFragment()
		if _, err := fr.ReadMetaHeaders.Write(frag); err != nil {
			return mh, nil, http2ConnectionError(errHttp2CodeCompression)
		}
		if hc.HeadersEnded() {
			break
		}
		if f, data, err := fr.ReadFrame(); err != nil {
			return nil, nil, err
		} else {
			hc = f.(*http2ContinuationFrame)
			allData = append(allData, data...)
		}
	}
	mh.Http2HeadersFrame.headerFragBuf = nil
	if err := fr.ReadMetaHeaders.Close(); err != nil {
		return mh, nil, http2ConnectionError(errHttp2CodeCompression)
	}
	return mh, allData, nil
}
