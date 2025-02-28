package http2

import (
	"bytes"
	"errors"
	"io"

	"github.com/gospider007/tools"
)

type Spec struct {
	Pri          string
	Sm           string
	Settings     []Http2Setting
	ConnFlow     uint32
	OrderHeaders [][2]string
	Priority     Http2PriorityParam
	StreamID     uint32
	raw          []byte
	initData     []byte
}

func (obj *Spec) Hex() string {
	return tools.Hex(obj.raw)
}
func (obj *Spec) Bytes() []byte {
	return obj.raw
}

func (obj *Spec) Map() map[string]any {
	rawContent := obj.Bytes()
	rawContent = rawContent[bytes.Index(rawContent, []byte("\r\n\r\n"))+4:]
	rawContent = rawContent[bytes.Index(rawContent, []byte("\r\n\r\n"))+4:]
	reader := Http2NewReaderFramer(bytes.NewReader(rawContent))
	streams := []map[string]any{}
readF:
	for {
		f, err := reader.ReadFrame()
		if err != nil {
			break readF
		}
		switch frame := f.(type) {
		case *Http2MetaHeadersFrame:
			fields := []map[string]any{}
			data := map[string]any{
				"type":     frame.Type,
				"name":     "Http2MetaHeadersFrame",
				"streamID": frame.StreamID,
				"priority": map[string]any{
					"streamDep": frame.Priority.StreamDep,
					"exclusive": frame.Priority.Exclusive,
					"weight":    frame.Priority.Weight,
				},
			}
			for _, hf := range frame.RegularFields() {
				fields = append(fields, map[string]any{
					"name":  hf.Name,
					"value": hf.Value,
				})
			}
			data["headers"] = fields
			streams = append(streams, data)
			break readF
		case *Http2SettingsFrame:
			data := map[string]any{
				"type":     frame.Type,
				"name":     "Http2SettingsFrame",
				"streamID": frame.StreamID,
			}
			settings := []map[string]any{}
			frame.ForeachSetting(func(hs Http2Setting) error {
				settings = append(settings, map[string]any{
					"id":  hs.ID,
					"val": hs.Val,
				})
				return nil
			})
			data["settings"] = settings
			streams = append(streams, data)
		case *Http2WindowUpdateFrame:
			data := map[string]any{
				"type":     frame.Type,
				"name":     "Http2WindowUpdateFrame",
				"streamID": frame.StreamID,
				"connFlow": frame.Increment,
			}
			streams = append(streams, data)
		case *Http2PingFrame:
			data := map[string]any{
				"type":     frame.Type,
				"name":     "Http2PingFrame",
				"streamID": frame.StreamID,
				"isAck":    frame.IsAck(),
				"data":     frame.Data,
			}
			streams = append(streams, data)
		}
	}
	results := map[string]any{
		"pri":          obj.Pri,
		"sm":           obj.Sm,
		"settings":     obj.Settings,
		"connFlow":     obj.ConnFlow,
		"orderHeaders": obj.OrderHeaders,
		"priority": map[string]any{
			"streamDep": obj.Priority.StreamDep,
			"exclusive": obj.Priority.Exclusive,
			"weight":    obj.Priority.Weight,
		},
		"streams": streams,
	}
	return results
}

func ParseSpec(raw []byte) (*Spec, error) {
	i := bytes.Index(raw, []byte("\r\n\r\n"))
	if i == -1 {
		return nil, errors.New("not found \\r\\n")
	}
	pri := raw[:i]
	rawContent := raw[i+4:]
	if i = bytes.Index(rawContent, []byte("\r\n\r\n")); i == -1 {
		return nil, errors.New("not found \\r\\n")
	}
	sm := rawContent[:i]
	rawContent = rawContent[i+4:]
	r := bytes.NewReader(rawContent)
	reader := Http2NewReaderFramer(r)
	var orderHeaders [][2]string
	settings := []Http2Setting{}
	var jq int
	var connFlow uint32
	var streamID uint32
	var priority Http2PriorityParam
	var ok bool
readF:
	for {
		f, err := reader.ReadFrame()
		if err != nil {
			if err == io.EOF {
				break readF
			}
			return nil, err
		}
		switch frame := f.(type) {
		case *Http2MetaHeadersFrame:
			names := [][2]string{}
			for _, hf := range frame.RegularFields() {
				names = append(names, [2]string{
					hf.Name,
					hf.Value,
				})
			}
			orderHeaders = names
			priority = frame.Priority
			streamID = frame.StreamID
			ok = true
			break readF
		case *Http2DataFrame:
			return nil, errors.New("Http2DataFrame")
		case *Http2GoAwayFrame:
			return nil, errors.New("Http2GoAwayFrame")
		case *Http2RSTStreamFrame:
			return nil, errors.New("Http2RSTStreamFrame")
		case *Http2SettingsFrame:
			jq = r.Len()
			frame.ForeachSetting(func(hs Http2Setting) error {
				settings = append(settings, hs)
				return nil
			})
		case *Http2PushPromiseFrame:
			return nil, errors.New("Http2PushPromiseFrame")
		case *Http2WindowUpdateFrame:
			jq = r.Len()
			connFlow = frame.Increment
		case *Http2PingFrame:
			jq = r.Len()
		default:
			return nil, errors.New("Http2UnknownFramep")
		}
	}
	if !ok {
		return nil, errors.New("not found stream")
	}
	return &Spec{
		raw:          raw,
		Pri:          string(pri),
		Sm:           string(sm),
		Settings:     settings,
		ConnFlow:     connFlow,
		OrderHeaders: orderHeaders,
		Priority:     priority,
		initData:     rawContent[:len(rawContent)-jq],
		StreamID:     streamID,
	}, nil
}
