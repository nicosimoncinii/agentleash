package claude

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// object is a JSON object that remembers key order and keeps values as raw JSON,
// so rewriting a user's settings file only touches the parts agentleash manages.
type object struct {
	keys []string
	vals map[string]json.RawMessage
}

func newObject() *object { return &object{vals: map[string]json.RawMessage{}} }

// parseObject decodes a JSON object, preserving key order. On duplicate keys the
// last value wins (like encoding/json) at the position of the first occurrence.
func parseObject(data []byte) (*object, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	o := newObject()
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected token %v", tok)
		}
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, err
		}
		o.set(key, val)
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		return nil, err
	}
	if _, err := dec.Token(); err == nil {
		return nil, errors.New("unexpected data after JSON object")
	}
	return o, nil
}

func (o *object) get(key string) (json.RawMessage, bool) {
	v, ok := o.vals[key]
	return v, ok
}

func (o *object) set(key string, val json.RawMessage) {
	if _, ok := o.vals[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = val
}

func (o *object) del(key string) {
	if _, ok := o.vals[key]; !ok {
		return
	}
	delete(o.vals, key)
	for i, k := range o.keys {
		if k == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

func (o *object) len() int { return len(o.keys) }

// raw renders the object as compact JSON.
func (o *object) raw() (json.RawMessage, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := marshalJSON(k)
		if err != nil {
			return nil, err
		}
		buf.Write(bytes.TrimSpace(kb))
		buf.WriteByte(':')
		if err := json.Compact(&buf, o.vals[k]); err != nil {
			return nil, err
		}
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// render renders the object with stable 2-space indentation and a trailing newline.
func (o *object) render() ([]byte, error) {
	compact, err := o.raw()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, compact, "", "  "); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

// childObject returns the object stored under key. ok is false when the key is absent.
func (o *object) childObject(key string) (child *object, ok bool, err error) {
	raw, present := o.get(key)
	if !present {
		return nil, false, nil
	}
	child, err = parseObject(raw)
	if err != nil {
		return nil, false, fmt.Errorf("must be a JSON object: %w", err)
	}
	return child, true, nil
}

// childArray returns the array stored under key. ok is false when the key is absent.
func (o *object) childArray(key string) (items []json.RawMessage, ok bool, err error) {
	raw, present := o.get(key)
	if !present {
		return nil, false, nil
	}
	if err := json.Unmarshal(raw, &items); err != nil || items == nil {
		return nil, false, errors.New("must be a JSON array")
	}
	return items, true, nil
}

func (o *object) setObject(key string, child *object) error {
	raw, err := child.raw()
	if err != nil {
		return err
	}
	o.set(key, raw)
	return nil
}

func (o *object) setArray(key string, items []json.RawMessage) error {
	// Built by hand: json.Marshal would HTML-escape the user's raw values.
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, it := range items {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := json.Compact(&buf, it); err != nil {
			return err
		}
	}
	buf.WriteByte(']')
	o.set(key, buf.Bytes())
	return nil
}
