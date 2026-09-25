"""재현 가능한 시연을 위한 모의 시계 (KST)."""

from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))


class SimClock:
    def __init__(self, start: datetime):
        self._now = start

    def now(self) -> datetime:
        return self._now

    def iso(self) -> str:
        return self._now.isoformat()

    def advance(self, seconds: float) -> None:
        self._now += timedelta(seconds=seconds)
