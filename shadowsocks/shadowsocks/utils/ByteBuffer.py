from typing import Optional

class ByteBuffer:
    def __init__(self):
        self._buffer = bytearray()
        self._head = 0

    def read(self, length: int) -> bytes:
        '''Remove and return first `length` bytes from buffer.'''
        ret = bytes(self._buffer[self._head: self._head + length])
        self._head = min(len(self._buffer), self._head + length)
        return ret

    def write(self, data: bytes):
        '''Write data into buffer.'''
        self._try_clean_unused()
        self._buffer += data

    def as_bytes(self, length: Optional[int] = None) -> bytes:
        '''Return the first `length` bytes from buffer.'''
        if length is None: 
            # Return the whole buffer
            # Set length to len(self._buffer) guarantee to cover the whole buffer.
            length = len(self._buffer)

        return bytes(self._buffer[self._head: self._head + length])
    
    def _should_clean_unused(self):
        occupied = len(self)
        vacant = self._head
        
        if vacant < 4 * 1024: # 4kB
            return False
        
        return occupied == 0 or vacant / occupied > 2

    def _try_clean_unused(self):
        if not self._should_clean_unused(): return

        self._buffer = self._buffer[self._head:]
        self._head = 0

    def __len__(self):
        '''Return length of current buffer.'''
        return len(self._buffer) - self._head
    
    def __bool__(self):
        return len(self) != 0