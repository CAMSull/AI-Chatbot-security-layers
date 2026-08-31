from app.security.rate_limit import InMemoryRateLimiter


def test_requests_within_limit_are_allowed():
    limiter = InMemoryRateLimiter(max_requests=3, window_seconds=60)
    for _ in range(3):
        result = limiter.check("user-a")
        assert result.allowed

def test_requests_over_limit_are_denied():
    limiter = InMemoryRateLimiter(max_requests=2, window_seconds=60)
    assert limiter.check("user-b").allowed
    assert limiter.check("user-b").allowed
    denied = limiter.check("user-b")
    assert not denied.allowed
    assert denied.retry_after_seconds > 0


def test_limits_are_tracked_per_key():
    limiter = InMemoryRateLimiter(max_requests=1, window_seconds=60)
    assert limiter.check("user-c").allowed
    assert not limiter.check("user-c").allowed
    # A different user has an independent bucket.
    assert limiter.check("user-d").allowed


def test_window_resets_after_expiry():
    limiter = InMemoryRateLimiter(max_requests=1, window_seconds=0)
    assert limiter.check("user-e").allowed
    # window_seconds=0 means the window is always considered expired on the next check
    assert limiter.check("user-e").allowed
