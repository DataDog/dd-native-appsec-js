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

describe('DDWAF', () => {
  it('should return the version', () => {
    const v = DDWAF.version()

    assert.strictEqual(`${v.major}.${v.minor}.${v.patch}`, pkg.libddwaf_version)
  })

  it('should have rulesInfo', () => {
    const waf = new DDWAF(rules)

    assert.deepStrictEqual(waf.rulesInfo, {
      version: '1.3.1',
      loaded: 6,
      failed: 3,
      errors: {
        'missing key \'regex\'': [
          'invalid_1'
        ],
        'invalid regular expression: *': [
          'invalid_2',
          'invalid_3'
        ]
      }
    })
  })

  it('should collect an attack and cleanup everything', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()

    const result = context.run({
      'server.request.headers.no_cookies': 'value_ATTack',
      x: new Array(4096).fill('x').join(''),
      y: new Array(4097).fill('y').join(''),
      z: new Array(4097).fill('z')
    }, TIMEOUT)

    assert.strictEqual(result.timeout, false)
    assert.strictEqual(result.action, 'monitor')
    assert(result.data)
    assert(!context.disposed)

    context.dispose()
    assert(context.disposed)

    assert.throws(() => context.run({ 'server.request.headers.no_cookies': 'value_ATTack' }, TIMEOUT))
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

    assert.strictEqual(result.action, 'monitor')
    assert(result.data)
  })

  it('should refuse invalid rule', () => {
    assert.throws(() => new DDWAF({}))
    assert.throws(() => new DDWAF(''))
  })

  it('should refuse to run with bad signatures', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()

    assert.throws(() => context.run())
    assert.throws(() => context.run('', TIMEOUT))
    assert.throws(() => context.run({ 'server.request.headers.no_cookies': 'value_attack' }, -1))
    assert.throws(() => context.run({ 'server.request.headers.no_cookies': 'value_attack' }, 0))
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
      [{ a: 1, b: 2 }, '[object Object]'],
      [['a', 2, 'c'], 'a,2,c'],
      [/regex/, '/regex/'],
      [function fn () {}, 'function fn () {}']
    ])

    const waf = new DDWAF(rules)

    for (const [key, expected] of possibleKeys) {
      const context = waf.createContext()

      const result = context.run({
        key_attack: {
          [key]: 'value'
        }
      }, TIMEOUT)

      assert.strictEqual(result.action, 'monitor')
      assert(result.data)
      assert.strictEqual(JSON.parse(result.data)[0].rule_matches[0].parameters[0].value, expected)
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
            key_attack: value
          }
        }, TIMEOUT)
      })

      assert.strictEqual(result.action, 'monitor')
      assert(result.data)
      assert.strictEqual(JSON.parse(result.data)[0].rule_matches[0].parameters[0].value, 'key_attack')
    }
  })

  it('should obfuscate keys', () => {
    const waf = new DDWAF(rules, {
      obfuscatorKeyRegex: 'password'
    })
    const context = waf.createContext()

    const result = context.run({
      value_attack: {
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
      obfuscatorValueRegex: 'value_attack'
    })
    const context = waf.createContext()

    const result = context.run({
      'server.request.headers.no_cookies': {
        header: 'value_attack'
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

    const context1 = waf.createContext()
    const result1 = context1.run({
      'server.response.status': {
        a0: '404'
      }
    }, TIMEOUT)
    assert.strictEqual(result1.action, 'monitor')
    assert(result1.data)

    const item = {}
    for (let i = 0; i < 1000; ++i) {
      item[`a${i}`] = `${1}`
    }

    const context2 = waf.createContext()
    const result2 = context2.run({
      'server.response.status': item
    }, TIMEOUT)
    assert(!result2.action)
    assert(!result2.data)
  })

  it('should match a moderately deeply nested object', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()

    const result = context.run({
      'server.request.headers.no_cookies': createNestedObject(5, { header: 'value_attack' })
    }, TIMEOUT)

    assert.strictEqual(result.action, 'monitor')
    assert(result.data)
  })

  it('should not match an extremely deeply nested object', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()

    const result = context.run({
      'server.request.headers.no_cookies': createNestedObject(100, { header: 'value_attack' })
    }, TIMEOUT)

    assert(!result.action)
    assert(!result.data)
  })

  it('should not limit the rules object', () => {
    const waf = new DDWAF(rules)

    // test first item in big rule
    const context1 = waf.createContext()
    const result1 = context1.run({
      'server.request.body': { a: '.htaccess' }
    }, TIMEOUT)
    assert(result1.action)
    assert(result1.data)

    // test last item in big rule
    const context2 = waf.createContext()
    const result2 = context2.run({
      'server.request.body': { a: 'yarn.lock' }
    }, TIMEOUT)
    assert(result2.action)
    assert(result2.data)
  })
})

function createNestedObject (n, obj) {
  if (n > 0) {
    return { a: createNestedObject(n - 1, obj) }
  }

  return obj
}
