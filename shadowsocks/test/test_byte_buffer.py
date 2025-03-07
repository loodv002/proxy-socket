import unittest

from shadowsocks.utils.ByteBuffer import ByteBuffer


class TestUtilsByteBuffer(unittest.TestCase):
    def test_ByteBuffer_basic(self):
        operations = [
            ('write', (b'12345', )),
            ('read', (3, )),
            ('write', (b'6789abc', )),
            ('as_bytes', (9, )),
        ]
        self.assertTrue(self._run_testcase(operations))

    def test_ByteBuffer_large_data(self):
        operations = [
            ('write', (b'1' * (1000000), )),
            ('read', (700000, )),
            ('write', (b'2' * (1000000), )),
            ('as_bytes', (10000, )),
        ]
        self.assertTrue(self._run_testcase(operations))
    
    @classmethod
    def _run_testcase(cls, operations):
        answer = cls._simulate(operations)
        
        buffer = ByteBuffer()
        return_value = []
        for operation, args in operations:
            return_value.append(getattr(buffer, operation)(*args))
        
        return return_value == answer
    
    @staticmethod
    def _simulate(operations):
        buffer = bytearray()
        return_value = []

        for operation, args in operations:
            if operation == 'read':
                return_value.append(bytes(buffer[:args[0]]))
                buffer = buffer[args[0]:]
            elif operation == 'write':
                buffer += args[0]
                return_value.append(None)
            elif operation == 'as_bytes':
                return_value.append(bytes(buffer[:args[0]]))

        return return_value