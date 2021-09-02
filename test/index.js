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
    const result = context.run({ 'server.request.headers.no_cookies': 'HELLO world' }, 10000)
    assert.strictEqual(result.action, 'monitor')
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
