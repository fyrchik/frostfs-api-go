package signature

func newBuffer(buf []byte, args ...stableMarshaler) []byte {
	maxSize := 0
	for i := range args {
		if args[i] == nil {
			continue
		}
		if sz := args[i].StableSize(); sz > maxSize {
			maxSize = sz
		}
	}
	if cap(buf) < maxSize {
		buf = make([]byte, maxSize)
	}
	return buf
}
