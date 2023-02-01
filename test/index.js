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

    assert.strictEqual(v, pkg.libddwaf_version)
  })

  it('should have rulesInfo', () => {
    const waf = new DDWAF(rules)

    assert.deepStrictEqual(waf.rulesInfo, {
      version: '1.3.1',
      loaded: 7,
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
    assert.strictEqual(result.status, 'match')
    assert(result.data)
    assert.deepStrictEqual(result.actions, [])
    assert(!context.disposed)

    context.dispose()
    assert(context.disposed)

    assert.throws(() => {
      context.run({ 'server.request.headers.no_cookies': 'value_ATTack' }, TIMEOUT)
    }, new Error('Calling run on a disposed context'))
    assert(!waf.disposed)

    waf.dispose()
    assert(waf.disposed)

    assert.throws(() => {
      waf.createContext()
    }, new Error('Calling createContext on a disposed DDWAF instance'))
  })

  it('should collect an attack with updated rule data', () => {
    const IP_TO_BLOCK = '123.123.123.123'

    const waf = new DDWAF(rules)
    const context = waf.createContext()
    const resultBeforeUpdatingRuleData = context.run({ 'http.client_ip': IP_TO_BLOCK }, TIMEOUT)
    assert(!resultBeforeUpdatingRuleData.status)

    const ruleData = [
      {
        id: 'blocked_ips',
        type: 'ip_with_expiration',
        data: [{ value: IP_TO_BLOCK }]
      }
    ]

    waf.updateRuleData(ruleData)
    const resultAfterUpdatingRuleData = context.run({ 'http.client_ip': IP_TO_BLOCK }, TIMEOUT)

    assert.strictEqual(resultAfterUpdatingRuleData.timeout, false)
    assert.strictEqual(resultAfterUpdatingRuleData.status, 'match')
    assert(resultAfterUpdatingRuleData.data)
    assert.deepStrictEqual(resultAfterUpdatingRuleData.actions, ['block'])
    assert(!context.disposed)
  })

  it('should refuse to update rule data with bad signature', () => {
    const waf = new DDWAF(rules)
    assert.throws(() => waf.updateRuleData(), new Error('Wrong number of arguments, expected 1'))
    assert.throws(() => waf.updateRuleData({}), new TypeError('First argument must be an array'))
  })

  it('should refuse to update rule data when WAF has been disposed', () => {
    const waf = new DDWAF(rules)
    waf.dispose()
    assert.throws(() => waf.updateRuleData([]), new Error('Could not update rule data on a disposed WAF'))
  })

  it('should refuse to toggle rules with bad signature', () => {
    const waf = new DDWAF(rules)
    assert.throws(() => waf.toggleRules(), new Error('Wrong number of arguments, expected 1'))
    assert.throws(() => waf.toggleRules(73), new TypeError('First argument must be an object'))
  })

  it('should not collect an attack on a toggled off rule', () => {
    const waf = new DDWAF(rules)
    const contextToggledOff = waf.createContext()

    waf.toggleRules({
      value_matchall: false
    })

    const resultToggledOff = contextToggledOff.run({
      value_attack: 'matchall'
    }, TIMEOUT)

    assert(!resultToggledOff.status)
    assert(!resultToggledOff.data)

    const contextToggledOn = waf.createContext()
    waf.toggleRules({
      value_matchall: true
    })

    const resultToggledOn = contextToggledOn.run({
      value_attack: 'matchall'
    }, TIMEOUT)

    assert.strictEqual(resultToggledOn.timeout, false)
    assert.strictEqual(resultToggledOn.status, 'match')
    assert(resultToggledOn.data)
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
    assert.throws(() => new DDWAF({}), new Error('Invalid rules'))
    assert.throws(() => new DDWAF(''), new TypeError('First argument must be an object'))
  })

  it('should refuse to run with bad signatures', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()

    assert.throws(() => context.run(), new Error('Wrong number of arguments, expected 2'))
    assert.throws(() => context.run('', TIMEOUT), new TypeError('First argument must be an object'))
    const err = new TypeError('Second argument must be greater than 0')
    assert.throws(() => context.run({ 'server.request.headers.no_cookies': 'value_attack' }, -1), err)
    assert.throws(() => context.run({ 'server.request.headers.no_cookies': 'value_attack' }, 0), err)
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

      assert.strictEqual(result.status, 'match')
      assert(result.data)
      assert.strictEqual(JSON.parse(result.data)[0].rule_matches[0].parameters[0].value, expected)
    }
  })

  it('should parse values correctly', () => {
    const possibleValues = new Map([
      [undefined, undefined],
      [null, undefined],
      [false, '0'],
      [true, '1'],
      [42, '42'],
      [-42, '-42'],
      [42.42, '42.42'],
      [Infinity, 'Infinity'],
      [NaN, 'NaN'],
      [BigInt(42), undefined],
      ['str', 'str'],
      [{ a: 1, b: 2 }, '1'],
      [['a', 2, 'c'], 'a'],
      [/regex/, undefined],
      [function fn () {}, undefined]
    ])

    const waf = new DDWAF(rules)

    for (const [value, expected] of possibleValues) {
      const context = waf.createContext()

      const result = context.run({
        value_attack: {
          key: value
        }
      }, TIMEOUT)

      if (expected !== undefined) {
        assert.strictEqual(result.status, 'match')
        assert(result.data)
        assert.strictEqual(JSON.parse(result.data)[0].rule_matches[0].parameters[0].value, expected)
      }
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
    assert.strictEqual(result1.status, 'match')
    assert(result1.data)

    const item = {}
    for (let i = 0; i < 1000; ++i) {
      item[`a${i}`] = `${i}`
    }

    const context2 = waf.createContext()
    const result2 = context2.run({
      'server.response.status': item
    }, TIMEOUT)
    assert(!result2.status)
    assert(!result2.data)
  })

  it('should match a moderately deeply nested object', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()

    const result = context.run({
      'server.request.headers.no_cookies': createNestedObject(5, { header: 'value_attack' })
    }, TIMEOUT)

    assert.strictEqual(result.status, 'match')
    assert(result.data)
  })

  it('should not match an extremely deeply nested object', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()

    const result = context.run({
      'server.request.headers.no_cookies': createNestedObject(100, { header: 'value_attack' })
    }, TIMEOUT)

    assert(!result.status)
    assert(!result.data)
  })

  it('should not limit the rules object', () => {
    const waf = new DDWAF(rules)

    // test first item in big rule
    const context1 = waf.createContext()
    const result1 = context1.run({
      'server.request.body': { a: '.htaccess' }
    }, TIMEOUT)
    assert(result1.status)
    assert(result1.data)

    // test last item in big rule
    const context2 = waf.createContext()
    const result2 = context2.run({
      'server.request.body': { a: 'yarn.lock' }
    }, TIMEOUT)
    assert(result2.status)
    assert(result2.data)
  })
})

function createNestedObject (n, obj) {
  if (n > 0) {
    return { a: createNestedObject(n - 1, obj) }
  }

  return obj
}
