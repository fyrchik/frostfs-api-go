package client

func (c *callOptions) getBuffer(sz int) []byte {
	if sz < cap(c.buffer) {
		return c.buffer[:sz]
	}

	c.buffer = make([]byte, sz)
	return c.buffer
}
