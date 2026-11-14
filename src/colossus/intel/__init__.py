"""Threat intelligence: OSV/KEV parsing, feed cache, replay and dependency matching."""

from .cache import FeedCache, refresh
from .fetcher import FeedFetcher, FeedPayload, GatewayFeedFetcher
from .matching import advisory_status, evaluate_package, evaluate_range, match_inventory
from .models import Advisory, DependencyEntry, FeedFreshness, IntelMatch, KevCatalog
from .parsers import parse_kev, parse_osv

__all__ = [
    "Advisory",
    "DependencyEntry",
    "FeedCache",
    "FeedFetcher",
    "FeedFreshness",
    "FeedPayload",
    "GatewayFeedFetcher",
    "IntelMatch",
    "KevCatalog",
    "advisory_status",
    "evaluate_package",
    "evaluate_range",
    "match_inventory",
    "parse_kev",
    "parse_osv",
    "refresh",
]
