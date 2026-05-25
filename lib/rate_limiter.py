"""
SECEOKNIGHT Rate Limiting Module
File: lib/rate_limiter.py
Purpose: Token bucket rate limiting, exponential backoff, circuit breaker
"""

import time
import threading
from typing import Optional
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class TokenBucket:
    """Token bucket algorithm for rate limiting."""

    def __init__(self, capacity: float, refill_rate: float):
        """
        Args:
            capacity: Max tokens (burst size)
            refill_rate: Tokens per second
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def acquire(self, tokens: float = 1, blocking: bool = True) -> bool:
        """Get tokens, optionally wait if unavailable."""
        with self.lock:
            self._refill()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True

            if not blocking:
                return False

            # Calculate wait time
            needed = tokens - self.tokens
            wait_time = needed / self.refill_rate
            logger.debug(f"Rate limit: waiting {wait_time:.2f}s")

            time.sleep(wait_time)
            self._refill()
            self.tokens -= tokens
            return True

    def _refill(self):
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill
        refilled = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + refilled)
        self.last_refill = now


class ExponentialBackoff:
    """Exponential backoff for retries."""

    def __init__(self, base_delay: float = 1, max_delay: float = 300, max_retries: int = 5):
        """
        Args:
            base_delay: Initial delay in seconds
            max_delay: Maximum delay in seconds
            max_retries: Maximum retry attempts
        """
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.max_retries = max_retries
        self.attempt = 0

    def reset(self):
        """Reset retry counter."""
        self.attempt = 0

    def should_retry(self) -> bool:
        """Check if we should retry."""
        return self.attempt < self.max_retries

    def wait(self):
        """Wait before next retry."""
        if self.attempt >= self.max_retries:
            raise Exception(f"Max retries ({self.max_retries}) exceeded")

        # Exponential: 1s, 2s, 4s, 8s, 16s...
        delay = min(self.base_delay * (2 ** self.attempt), self.max_delay)
        self.attempt += 1

        logger.info(f"Retry attempt {self.attempt}/{self.max_retries}, waiting {delay}s")
        time.sleep(delay)


class CircuitBreaker:
    """Circuit breaker pattern for API health."""

    CLOSED = "CLOSED"      # Working normally
    OPEN = "OPEN"          # Failed, rejecting requests
    HALF_OPEN = "HALF_OPEN"  # Testing recovery

    def __init__(self, failure_threshold: int = 5, timeout: int = 60):
        """
        Args:
            failure_threshold: Failures before opening circuit
            timeout: Seconds before trying again
        """
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.state = self.CLOSED
        self.failures = 0
        self.last_failure_time = None
        self.lock = threading.Lock()

    def record_success(self):
        """Mark successful call."""
        with self.lock:
            self.failures = 0
            self.state = self.CLOSED

    def record_failure(self):
        """Mark failed call."""
        with self.lock:
            self.failures += 1
            self.last_failure_time = time.time()

            if self.failures >= self.failure_threshold:
                self.state = self.OPEN
                logger.warning(f"Circuit breaker OPEN after {self.failures} failures")

    def is_available(self) -> bool:
        """Check if circuit allows calls."""
        with self.lock:
            if self.state == self.CLOSED:
                return True

            if self.state == self.OPEN:
                # Check if timeout expired
                elapsed = time.time() - self.last_failure_time
                if elapsed > self.timeout:
                    self.state = self.HALF_OPEN
                    self.failures = 0
                    logger.info("Circuit breaker HALF_OPEN - testing recovery")
                    return True
                return False

            # HALF_OPEN - try one call
            return True

    def get_state(self) -> str:
        """Get current state."""
        return self.state


class RateLimiter:
    """Combined rate limiting with backoff and circuit breaker."""

    def __init__(self, requests_per_second: float = 1, failure_threshold: int = 5):
        """
        Args:
            requests_per_second: Rate limit
            failure_threshold: Failures before circuit opens
        """
        # Token bucket: capacity = burst size, refill_rate = rps
        self.bucket = TokenBucket(capacity=5, refill_rate=requests_per_second)
        self.backoff = ExponentialBackoff(base_delay=1, max_delay=300, max_retries=5)
        self.circuit_breaker = CircuitBreaker(failure_threshold=failure_threshold)

    def wait_if_needed(self) -> bool:
        """
        Wait until we can make a request.

        Returns:
            True if allowed, False if circuit is broken
        """
        if not self.circuit_breaker.is_available():
            logger.warning("Circuit breaker OPEN - rejecting request")
            return False

        self.bucket.acquire(tokens=1, blocking=True)
        return True

    def record_success(self):
        """Mark successful API call."""
        self.circuit_breaker.record_success()
        self.backoff.reset()

    def record_failure(self):
        """Mark failed API call."""
        self.circuit_breaker.record_failure()

    def should_retry(self) -> bool:
        """Should we retry after failure."""
        return self.backoff.should_retry()

    def wait_for_retry(self):
        """Wait before retrying."""
        self.backoff.wait()

    def get_status(self) -> dict:
        """Get limiter status."""
        return {
            "circuit_state": self.circuit_breaker.state,
            "failures": self.circuit_breaker.failures,
            "retry_attempt": self.backoff.attempt,
            "tokens_available": self.bucket.tokens
        }
