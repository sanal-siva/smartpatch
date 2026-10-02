from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry
import time
from contextlib import contextmanager

registry = CollectorRegistry()

# API metrics
api_request_count = Counter(
    'api_requests_total',
    'Total API requests',
    ['endpoint', 'method'],
    registry=registry
)

api_request_duration = Histogram(
    'api_request_duration_seconds',
    'API request duration in seconds',
    ['endpoint'],
    registry=registry
)

# Cache metrics
cache_hits = Counter('cache_hits_total', 'Total cache hits', registry=registry)
cache_misses = Counter('cache_misses_total', 'Total cache misses', registry=registry)

cache_hit_rate = Gauge(
    'cache_hit_rate_percent',
    'Cache hit rate percentage',
    registry=registry
)

# AI Service metrics
ai_service_health = Gauge(
    'ai_service_health',
    'AI service health (1=healthy, 0=unhealthy)',
    registry=registry
)

ai_assessment_duration = Histogram(
    'ai_assessment_duration_seconds',
    'AI assessment duration',
    registry=registry
)

# Queue metrics
async_queue_depth = Gauge(
    'async_queue_depth',
    'Number of queued async operations',
    registry=registry
)

# PKG_DB sync metrics
pkg_db_sync_duration = Histogram(
    'pkg_db_sync_duration_seconds',
    'PKG_DB sync duration',
    registry=registry
)

pkg_db_packages = Gauge(
    'pkg_db_total_packages',
    'Total packages in PKG_DB',
    registry=registry
)

def init_metrics():
    pass

@contextmanager
def track_duration(metric, labels=None):
    start = time.time()
    try:
        yield
    finally:
        duration = time.time() - start
        if labels:
            metric.labels(*labels).observe(duration)
        else:
            metric.observe(duration)
