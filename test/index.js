/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
const { it, describe } = require('mocha')
const assert = require('assert')

const { DDWAF } = require('..')
const pkg = require('../package.json')
const rules = require('./rules.json')

const TIMEOUT = 9999e3

describe('DDWAF lifecycle', () => {
  it('should return the version', () => {
    const v = DDWAF.version()
    assert.strictEqual(v, pkg.libddwaf_version)
  })

  it('should have rulesInfo', () => {
    const waf = new DDWAF(rules)
    assert(waf.rulesInfo)
    assert.strictEqual(waf.rulesInfo.version, '1.3.1')
    assert.strictEqual(waf.rulesInfo.loaded, 6)
    assert.strictEqual(waf.rulesInfo.failed, 3)
    assert.deepStrictEqual(waf.rulesInfo.errors, {
      'missing key \'regex\'': [
        'invalid_1'
      ],
      'invalid regular expression: *': [
        'invalid_2',
        'invalid_3'
      ]
    })
  })

  it('should collect an attack and cleanup everything', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()
    const result = context.run({
      'server.request.headers.no_cookies': 'HELLO world',
      x: new Array(4096).fill('x').join(''),
      y: new Array(4097).fill('y').join(''),
      z: new Array(4097).fill('z')
    }, TIMEOUT)
    assert.strictEqual(result.status, 'match')
    assert.strictEqual(result.timeout, false)
    assert(result.data)
    assert(!context.disposed)
    context.dispose()
    assert(context.disposed)
    assert.throws(() => context.run({ 'server.request.headers.no_cookies': 'HELLO world' }, TIMEOUT))
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
    }, TIMEOUT)
    assert.strictEqual(result.status, 'match')
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
    assert.throws(() => context.run('', TIMEOUT))
    assert.throws(() => context.run({ 'server.request.headers.no_cookies': 'HELLO world' }, -1))
    assert.throws(() => context.run({ 'server.request.headers.no_cookies': 'HELLO world' }, 0))
  })

  it('should test blocking', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()
    const res1 = context.run({ 'http.client_ip': '127.0.0.1' }, TIMEOUT)
    const res2 = context.run({ 'http.client_ip': '166.2.4.2' }, TIMEOUT)
    assert.strictEqual(res1.status, undefined)
    assert.strictEqual(res1.actions, undefined)
    assert.strictEqual(res2.status, 'match')
    assert.deepStrictEqual(res2.actions, ['block'])
  })

  it('should parse keys correctly and match on value', () => {
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
        }, TIMEOUT)
      })

      assert.strictEqual(result.status, 'match')
      assert(result.data)
      assert.strictEqual(JSON.parse(result.data)[0].rule_matches[0].parameters[0].key_path[0], expected)
    }
  })

  it('should parse values correctly and match on key', () => {
    const possibleValues = new Set([
      undefined,
      null,
      false,
      true,
      42,
      -42,
      42.42,
      Infinity,
      NaN,
      BigInt(42),
      'str',
      Symbol(''),
      { a: 1, b: 2 },
      ['a', 2, 'c'],
      /regex/,
      function fn () {}
    ])

    const waf = new DDWAF(rules)

    for (const value of possibleValues) {
      const context = waf.createContext()

      let result

      assert.doesNotThrow(() => {
        result = context.run({
          'server.request.headers.no_cookies': {
            kattack: value
          }
        }, TIMEOUT)
      })

      assert.strictEqual(result.status, 'match')
      assert(result.data)
      assert.strictEqual(JSON.parse(result.data)[0].rule_matches[0].parameters[0].value, 'kattack')
    }
  })

  it('should obfuscate keys', () => {
    const waf = new DDWAF(rules, {
      obfuscatorKeyRegex: 'password'
    })
    const context = waf.createContext()

    const result = context.run({
      atk: {
        password: {
          a: 'sensitive'
        }
      }
    }, TIMEOUT)

    assert(result)
    assert(result.data)
    assert.strictEqual(JSON.parse(result.data)[0].rule_matches[0].parameters[0].value, '<Redacted>')
    assert.strictEqual(JSON.parse(result.data)[0].rule_matches[0].parameters[0].highlight[0], '<Redacted>')
  })

  it('should obfuscate values', () => {
    const waf = new DDWAF(rules, {
      obfuscatorValueRegex: 'hello world'
    })
    const context = waf.createContext()

    const result = context.run({
      'server.request.headers.no_cookies': {
        header: 'hello world'
      }
    }, TIMEOUT)

    assert(result)
    assert(result.data)
    assert.strictEqual(JSON.parse(result.data)[0].rule_matches[0].parameters[0].value, '<Redacted>')
    assert.strictEqual(JSON.parse(result.data)[0].rule_matches[0].parameters[0].highlight[0], '<Redacted>')
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
    }, TIMEOUT)
    assert.strictEqual(result0.status, 'match')

    const item = {}
    for (let i = 0; i < 1000; ++i) {
      item[`a${i}`] = `${i}`
    }

    const result = context.run({
      'server.response.status': item
    }, TIMEOUT)
    assert.strictEqual(result.action, undefined)
    assert(!result.data)
  })

  it('should match a moderately deeply nested object', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()
    const result = context.run({
      'server.request.headers.no_cookies': createNestedObject(5, { header: 'hello world' })
    }, TIMEOUT)
    assert.strictEqual(result.status, 'match')
    assert(result.data)
  })

  it('should not match an extremely deeply nested object', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()
    const result = context.run({
      'server.request.headers.no_cookies': createNestedObject(100, { header: 'hello world' })
    }, TIMEOUT)
    assert(!result.action)
    assert(!result.data)
  })

  it('should not limit the rules object', () => {
    const waf = new DDWAF(rules)

    let context = waf.createContext()
    let result = context.run({
      'server.request.body': { a: '.htaccess' }
    }, TIMEOUT)
    assert(result.status)
    assert(result.data)

    context = waf.createContext()
    result = context.run({
      'server.request.body': { a: 'yarn.lock' }
    }, TIMEOUT)
    assert(result.status)
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
