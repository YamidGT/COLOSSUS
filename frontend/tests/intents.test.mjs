import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mutationIntent } from '../.test-build/intents.js'

test('unresolved mutation retry retains identical identity; success starts a new intent', () => {
  const first = mutationIntent('POST', '/projects/p/cycles', '{}')
  const retry = mutationIntent('POST', '/projects/p/cycles', '{}')
  assert.equal(first.key, retry.key)
  retry.resolve()
  assert.notEqual(mutationIntent('POST', '/projects/p/cycles', '{}').key, first.key)
})

test('changed candidate or destination cannot reuse an old request key', () => {
  const first = mutationIntent('POST', '/cases/c/approve', '{"candidate_id":"a"}')
  const changed = mutationIntent('POST', '/cases/c/approve', '{"candidate_id":"b"}')
  assert.notEqual(first.key, changed.key)
  assert.notEqual(first.key, mutationIntent('POST', '/cases/d/approve', '{"candidate_id":"a"}').key)
})

test('late resolution cannot remove a newer explicitly keyed intent', () => {
  const first = mutationIntent('POST', '/projects/q/pause', '{}', 'first-key')
  const next = mutationIntent('POST', '/projects/q/pause', '{}', 'next-key')
  first.resolve()
  assert.equal(mutationIntent('POST', '/projects/q/pause', '{}').key, next.key)
  next.resolve()
})
