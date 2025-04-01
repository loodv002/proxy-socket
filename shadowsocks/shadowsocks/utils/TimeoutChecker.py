import time

from typing  import Optional, Union

Timeout = Union[int, float]

class TimeoutChecker:
    def __init__(self, 
                 timeout: Timeout,
                 start_time: Optional[float] = None):
        
        start_time = start_time or time.time()
        self._expire_time = start_time + timeout
        self._blocking = (timeout != 0)

    def timeout_expired(self) -> bool:
        '''Check if timeout expired. 
        

        Returns:
            Whether timeout expired. If timout initiated by 0, always return False.
        '''        

        return (self._blocking and time.time() > self._expire_time)