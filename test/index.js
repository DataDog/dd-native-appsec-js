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

  it('should parse keys correctly', () => {
    const possibleKeys = new Map([
      [undefined, 'undefined'],
      [null, 'null'],
      [false, 'false'],
      [true, 'true'],
      [42, '42'],
      [-42, '-42'],
      [42.42, '42.42'],
      [Infinity, 'Infinity'],
      [NaN, 'NaN'],
      [BigInt(42), '42'],
      ['str', 'str'],
      // [Symbol(), ''], // we don't have a way to serialize symbols for now
      [{ a: 1, b: 2 }, '[object Object]'],
      [['a', 2, 'c'], 'a,2,c'],
      [/regex/, '/regex/'],
      [function fn () {}, 'function fn () {}']
    ])

    const waf = new DDWAF(rules)

    for (const [value, expected] of possibleKeys) {
      const context = waf.createContext()

      let result

      assert.doesNotThrow(() => {
        result = context.run({
          'server.request.headers.no_cookies': {
            [value]: 'hello world'
          }
        }, 10000)
      })

      assert.strictEqual(result.action, 'monitor')
      assert(result.data)
      assert.strictEqual(JSON.parse(result.data)[0].rule_matches[0].parameters[0].key_path[0], expected)
    }
  })

  it('should parse values correctly', () => {
    const possibleValues = new Map([
      [undefined, ''],
      [null, ''],
      [false, ''],
      [true, ''],
      [42, ''],
      [-42, ''],
      [42.42, ''],
      [Infinity, ''],
      [NaN, ''],
      [BigInt(42), ''],
      ['str', ''],
      [Symbol(''), ''],
      [{ a: 1, b: 2 }, ''],
      [['a', 2, 'c'], ''],
      [/regex/, ''],
      [function fn () {}, '']
    ])

    const waf = new DDWAF(rules)

    for (const [value, expected] of possibleValues) {
      const context = waf.createContext()

      let result

      assert.doesNotThrow(() => {
        result = context.run({
          'server.request.headers.no_cookies': {
            'kattack': value
          }
        }, 10000)
      })

      assert.strictEqual(result.action, 'monitor')
      assert(result.data)
      assert.strictEqual(JSON.parse(result.data)[0].rule_matches[0].parameters[0].value, expected)
    }
  })
})

describe('limit tests', () => {
  it('should ignore elements too far in the objects', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()

    const result0 = context.run({
      'server.response.status': {
        a0: '404'
      }
    }, 10000)
    assert.strictEqual(result0.action, 'monitor')

    const item = {}
    for (let i = 0; i < 1000; ++i) {
      item[`a${i}`] = `${i}`
    }

    const result = context.run({
      'server.response.status': item
    }, 10000)
    assert.strictEqual(result.action, undefined)
    assert(!result.data)
  })

  it('should match a moderately deeply nested object', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()
    const result = context.run({
      'server.request.headers.no_cookies': createNestedObject(5, { header: 'hello world' })
    }, 10000)
    assert.strictEqual(result.action, 'monitor')
    assert(result.data)
  })

  it('should not match an extremely deeply nested object', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()
    const result = context.run({
      'server.request.headers.no_cookies': createNestedObject(100, { header: 'hello world' })
    }, 10000)
    assert(!result.action)
    assert(!result.data)
  })

  it('should not limit the rules object', () => {
    const waf = new DDWAF(rules)

    let context = waf.createContext()
    let result = context.run({
      'server.request.body': { a: '.htaccess' }
    }, 10000)
    assert(result.action)
    assert(result.data)

    context = waf.createContext()
    result = context.run({
      'server.request.body': { a: 'yarn.lock' }
    }, 10000)
    assert(result.action)
    assert(result.data)
  })
})

describe('load tests', () => {
  // TODO: how to control memory impact of the addon
})

describe('worker tests', () => {
  // TODO: tests on how this works with workers
})

function createNestedObject (n, obj) {
  if (n > 0) {
    return { a: createNestedObject(n - 1, obj) }
  }

  return obj
}
