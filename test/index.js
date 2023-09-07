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

  it('should have diagnostics', () => {
    const waf = new DDWAF(rules)

    assert.deepStrictEqual(waf.diagnostics, {
      ruleset_version: '1.3.1',
      rules: {
        loaded: [
          'block_ip',
          'value_attack',
          'key_attack',
          'nfd-000-001',
          'value_matchall',
          'key_matchall',
          'long_rule'
        ],
        failed: ['invalid_1', 'invalid_2', 'invalid_3'],
        errors: {
          'missing key \'regex\'': [
            'invalid_1'
          ],
          'invalid regular expression: *': [
            'invalid_2',
            'invalid_3'
          ]
        }
      }
    })
  })

  it('should have requiredAddresses', () => {
    const waf = new DDWAF(rules)

    assert.deepStrictEqual(waf.requiredAddresses, new Set([
      'http.client_ip',
      'server.request.headers.no_cookies',
      'server.response.status',
      'value_attack',
      'key_attack',
      'server.request.body'
    ]))
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
    assert(result.events)
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

  describe('WAF update', () => {
    it('should throw an error when updating a disposed WAF instance', () => {
      const waf = new DDWAF(rules)
      waf.dispose()
      assert.throws(() => waf.update(rules), new Error('Could not update a disposed WAF instance'))
    })

    it('should throw an error when updating a WAF instance with no arguments', () => {
      const waf = new DDWAF(rules)
      assert.throws(() => waf.update(), new Error('Wrong number of arguments, expected at least 1'))
    })

    it('should throw a type error when updating a WAF instance with invalid arguments', () => {
      const waf = new DDWAF(rules)
      assert.throws(() => waf.update('string'), new TypeError('First argument must be an object'))
    })

    it('should throw an exception when WAF update has not been updated - nothing to update', () => {
      const waf = new DDWAF(rules)
      assert.throws(() => waf.update({}), new Error('WAF has not been updated'))
    })

    it('should update diagnostics and requiredAddresses when updating a WAF instance with new ruleSet', () => {
      const waf = new DDWAF({
        version: '2.2',
        metadata: {
          rules_version: '1.3.0'
        },
        rules: [{
          id: 'block_ip',
          name: 'block ip',
          tags: {
            type: 'ip_addresses',
            category: 'blocking'
          },
          conditions: [
            {
              parameters: {
                inputs: [
                  { address: 'http.client_ip' }
                ],
                data: 'blocked_ips'
              },
              operator: 'ip_match'
            }
          ],
          transformers: [],
          on_match: [
            'block'
          ]
        }]
      })

      assert.deepStrictEqual(waf.diagnostics, {
        ruleset_version: '1.3.0',
        rules: {
          loaded: ['block_ip'],
          failed: [],
          errors: {}
        }
      })
      assert.deepStrictEqual(waf.requiredAddresses, new Set([
        'http.client_ip'
      ]))

      waf.update(rules)
      assert.deepStrictEqual(waf.diagnostics, {
        ruleset_version: '1.3.1',
        rules: {
          loaded: [
            'block_ip',
            'value_attack',
            'key_attack',
            'nfd-000-001',
            'value_matchall',
            'key_matchall',
            'long_rule'
          ],
          failed: ['invalid_1', 'invalid_2', 'invalid_3'],
          errors: {
            'missing key \'regex\'': [
              'invalid_1'
            ],
            'invalid regular expression: *': [
              'invalid_2',
              'invalid_3'
            ]
          }
        }
      })
      assert.deepStrictEqual(waf.requiredAddresses, new Set([
        'http.client_ip',
        'server.request.headers.no_cookies',
        'server.response.status',
        'value_attack',
        'key_attack',
        'server.request.body'
      ]))

      waf.dispose()
    })

    it('should collect an attack with updated rule data', () => {
      const IP_TO_BLOCK = '123.123.123.123'

      const waf = new DDWAF(rules)
      const context = waf.createContext()
      const resultBeforeUpdatingRuleData = context.run({ 'http.client_ip': IP_TO_BLOCK }, TIMEOUT)
      assert(!resultBeforeUpdatingRuleData.status)

      const updateWithRulesData = {
        rules_data: [
          {
            id: 'blocked_ips',
            type: 'ip_with_expiration',
            data: [{ value: IP_TO_BLOCK }]
          }
        ]
      }

      waf.update(updateWithRulesData)
      const contextWithRuleData = waf.createContext()
      const resultAfterUpdatingRuleData = contextWithRuleData.run({ 'http.client_ip': IP_TO_BLOCK }, TIMEOUT)

      assert.strictEqual(resultAfterUpdatingRuleData.timeout, false)
      assert.strictEqual(resultAfterUpdatingRuleData.status, 'match')
      assert(resultAfterUpdatingRuleData.events)
      assert.deepStrictEqual(resultAfterUpdatingRuleData.actions, ['block'])
      assert(!context.disposed)
    })

    describe('Toggle rules', () => {
      [
        {
          testName: 'on a toggled off rule selected by id',
          rulesOverride: [
            {
              id: 'value_matchall',
              enabled: false
            }
          ]
        },
        {
          testName: 'on a toggled off rule selected by rules_target.tags',
          rulesOverride: [
            {
              rules_target: [
                {
                  tags: {
                    confidence: 1
                  }
                }
              ],
              enabled: false
            }
          ]
        }
      ].forEach((testData) => {
        it(`should not collect an attack ${testData.testName}`, () => {
          const waf = new DDWAF(rules)
          const contextToggledOn = waf.createContext()

          const resultToggledOn = contextToggledOn.run({
            value_attack: 'matchall'
          }, TIMEOUT)

          assert.strictEqual(resultToggledOn.timeout, false)
          assert.strictEqual(resultToggledOn.status, 'match')
          assert(resultToggledOn.events)

          const updateWithRulesOverride = {
            rules_override: testData.rulesOverride
          }

          waf.update(updateWithRulesOverride)
          const contextToggledOff = waf.createContext()

          const resultToggledOff = contextToggledOff.run({
            value_attack: 'matchall'
          }, TIMEOUT)

          assert(!resultToggledOff.status)
          assert(!resultToggledOff.events)
        })
      })
    })

    describe('Override on_match action', () => {
      [
        {
          testName: 'when on_match is overridden in a rule selected by id',
          rulesOverride: [
            {
              id: 'value_matchall',
              on_match: ['block']
            }
          ]
        },
        {
          testName: 'when on_match is overridden in a rule selected by rules_target.tags',
          rulesOverride: [
            {
              rules_target: [
                {
                  tags: {
                    confidence: 1
                  }
                }
              ],
              on_match: ['block']
            }
          ]
        }
      ].forEach((testData) => {
        it(`should return block action ${testData.testName}`, () => {
          const waf = new DDWAF(rules)
          const monitorContext = waf.createContext()

          const resultMonitor = monitorContext.run({
            value_attack: 'matchall'
          }, TIMEOUT)

          assert.strictEqual(resultMonitor.timeout, false)
          assert.strictEqual(resultMonitor.status, 'match')
          assert.deepStrictEqual(resultMonitor.actions, [])
          assert(resultMonitor.events)

          const updateWithRulesOverride = {
            rules_override: testData.rulesOverride
          }

          waf.update(updateWithRulesOverride)
          const blockContext = waf.createContext()

          const resultBlock = blockContext.run({
            value_attack: 'matchall'
          }, TIMEOUT)

          assert.strictEqual(resultBlock.timeout, false)
          assert.strictEqual(resultBlock.status, 'match')
          assert.deepStrictEqual(resultBlock.actions, ['block'])
        })
      })
    })
  })

  it('should support case_sensitive', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()

    const result = context.run({
      'server.response.status': '404'
    }, TIMEOUT)

    assert.strictEqual(result.status, 'match')
    assert(result.events)
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
      assert(result.events)
      assert.strictEqual(result.events[0].rule_matches[0].parameters[0].value, expected)
    }
  })

  it('should parse values correctly', () => {
    const possibleValues = new Map([
      [undefined, undefined],
      [null, undefined],
      [false, 'false'],
      [true, 'true'],
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
        assert(result.events)
        assert.strictEqual(result.events[0].rule_matches[0].parameters[0].value, expected)
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
    assert(result.events)
    assert.strictEqual(result.events[0].rule_matches[0].parameters[0].value, '<Redacted>')
    assert.strictEqual(result.events[0].rule_matches[0].parameters[0].highlight[0], '<Redacted>')
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
    assert(result.events)
    assert.strictEqual(result.events[0].rule_matches[0].parameters[0].value, '<Redacted>')
    assert.strictEqual(result.events[0].rule_matches[0].parameters[0].highlight[0], '<Redacted>')
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
    assert(result1.events)

    const item = {}
    for (let i = 0; i < 1000; ++i) {
      item[`a${i}`] = `${i}`
    }

    const context2 = waf.createContext()
    const result2 = context2.run({
      'server.response.status': item
    }, TIMEOUT)
    assert(!result2.status)
    assert(!result2.events)
  })

  it('should match a moderately deeply nested object', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()

    const result = context.run({
      'server.request.headers.no_cookies': createNestedObject(5, { header: 'value_attack' })
    }, TIMEOUT)

    assert.strictEqual(result.status, 'match')
    assert(result.events)
  })

  it('should not match an extremely deeply nested object', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()

    const result = context.run({
      'server.request.headers.no_cookies': createNestedObject(100, { header: 'value_attack' })
    }, TIMEOUT)

    assert(!result.status)
    assert(!result.events)
  })

  it('should not limit the rules object', () => {
    const waf = new DDWAF(rules)

    // test first item in big rule
    const context1 = waf.createContext()
    const result1 = context1.run({
      'server.request.body': { a: '.htaccess' }
    }, TIMEOUT)
    assert(result1.status)
    assert(result1.events)

    // test last item in big rule
    const context2 = waf.createContext()
    const result2 = context2.run({
      'server.request.body': { a: 'yarn.lock' }
    }, TIMEOUT)
    assert(result2.status)
    assert(result2.events)
  })
})

function createNestedObject (n, obj) {
  if (n > 0) {
    return { a: createNestedObject(n - 1, obj) }
  }

  return obj
}
