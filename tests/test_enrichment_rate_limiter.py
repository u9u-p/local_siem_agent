from freezegun import freeze_time

from app.enrichment.rate_limiter import DailyRateLimiter


def test_allows_up_to_daily_limit():
    limiter = DailyRateLimiter(daily_limit=3)
    assert limiter.try_acquire() is True
    assert limiter.try_acquire() is True
    assert limiter.try_acquire() is True
    assert limiter.try_acquire() is False


def test_resets_on_new_day():
    limiter = DailyRateLimiter(daily_limit=2)
    with freeze_time("2026-08-09"):
        assert limiter.try_acquire() is True
        assert limiter.try_acquire() is True
        assert limiter.try_acquire() is False

    with freeze_time("2026-08-10"):
        assert limiter.try_acquire() is True
