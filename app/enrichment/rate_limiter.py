from datetime import date


class DailyRateLimiter:
    def __init__(self, daily_limit: int) -> None:
        self._daily_limit = daily_limit
        self._count = 0
        self._window_date = date.today()

    def try_acquire(self) -> bool:
        today = date.today()
        if today != self._window_date:
            self._window_date = today
            self._count = 0
        if self._count >= self._daily_limit:
            return False
        self._count += 1
        return True
