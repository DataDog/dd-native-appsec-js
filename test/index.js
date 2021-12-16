/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
const { it, describe } = require('mocha')
const assert = require('assert')

const { DDWAF } = require('..')
const pkg = require('../package.json')
const rules = require('./rules.json')

describe('DDWAF lifecycle', () => {
  it('should return the version', () => {
    const v = DDWAF.version()
    assert.strictEqual([v.major, v.minor, v.patch].join('.'), pkg.libddwaf_version)
  })

  it('should collect an attack and cleanup everything', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()
    const result = context.run({
      'server.request.headers.no_cookies': 'HELLO world',
      x: new Array(4096).fill('x').join(''),
      y: new Array(4097).fill('y').join(''),
      z: new Array(4097).fill('z')
    }, 10000)
    assert.strictEqual(result.action, 'monitor')
    assert.strictEqual(result.timeout, false)
    assert(result.data)
    assert(!context.disposed)
    context.dispose()
    assert(context.disposed)
    assert.throws(() => context.run({ 'server.request.headers.no_cookies': 'HELLO world' }, 10000))
    assert(!waf.disposed)
    waf.dispose()
    assert(waf.disposed)
    assert.throws(() => waf.createContext())
  })

  it('should support case_sensitive', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()
    const result = context.run({
      'server.response.status': '404'
    }, 10000)
    assert.strictEqual(result.action, 'monitor')
    assert(result.data)
  })

  it('should refuse invalid rule', () => {
    assert.throws(() => new DDWAF({}))
  })

  it('should refuse to run with bad signatures', () => {
    assert.throws(() => new DDWAF(''))
    const waf = new DDWAF(rules)
    const context = waf.createContext()
    assert.throws(() => context.run())
    assert.throws(() => context.run('', 10000))
    assert.throws(() => context.run({ 'server.request.headers.no_cookies': 'HELLO world' }, -1))
    assert.throws(() => context.run({ 'server.request.headers.no_cookies': 'HELLO world' }, 0))
  })
})

describe('load tests', () => {
  // TODO: how to control memory impact of the addon
})

describe('worker tests', () => {
  // TODO: tests on how this works with workers
})
