"""Sandbox execution boundary (lane A). See docs/onboarding-sandbox.md.

The host never evaluates a shell string from a worker. Every container is
started from a fixed JobProfile and an IsolationProfile through argv lists.
"""
