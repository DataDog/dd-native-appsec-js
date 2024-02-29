/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
const { it, describe } = require('mocha')
const assert = require('assert')

const { DDWAF } = require('..')
const pkg = require('../package.json')
const rules = require('./rules.json')
const processor = require('./processor.json')

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
        addresses: {
          optional: [],
          required: [
            'http.client_ip',
            'server.request.headers.no_cookies',
            'server.response.status',
            'value_attack',
            'key_attack',
            'server.request.body'
          ]
        },
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

  it('should have knownAddresses', () => {
    const waf = new DDWAF(rules)

    assert.deepStrictEqual(waf.knownAddresses, new Set([
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
    const payload = {
      persistent: {
        'server.request.headers.no_cookies': 'value_ATTack',
        x: new Array(4096).fill('x').join(''),
        y: new Array(4097).fill('y').join(''),
        z: new Array(4097).fill('z')
      }
    }

    const result = context.run(payload, TIMEOUT)

    assert.strictEqual(result.timeout, false)
    assert.strictEqual(result.status, 'match')
    assert(result.events)
    assert.deepStrictEqual(result.actions, [])
    assert(!context.disposed)

    context.dispose()
    assert(context.disposed)

    assert.throws(() => {
      context.run(payload, TIMEOUT)
    }, new Error('Calling run on a disposed context'))
    assert(!waf.disposed)

    waf.dispose()
    assert(waf.disposed)

    assert.throws(() => {
      waf.createContext()
    }, new Error('Calling createContext on a disposed DDWAF instance'))
  })

  it('should collect different attacks on ephemeral addresses', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()
    let result = context.run({
      ephemeral: {
        'server.request.headers.no_cookies': 'value_ATTack'
      }
    }, TIMEOUT)

    assert.strictEqual(result.timeout, false)
    assert.strictEqual(result.status, 'match')
    assert.strictEqual(result.events[0].rule_matches[0].parameters[0].value, 'value_attack')
    assert.deepStrictEqual(result.actions, [])

    result = context.run({
      ephemeral: {
        'server.request.headers.no_cookies': 'other_attack'
      }
    }, TIMEOUT)

    assert.strictEqual(result.timeout, false)
    assert.strictEqual(result.status, 'match')
    assert.strictEqual(result.events[0].rule_matches[0].parameters[0].value, 'other_attack')
    assert.deepStrictEqual(result.actions, [])

    context.dispose()

    waf.dispose()
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

    it('should update diagnostics and knownAddresses when updating a WAF instance with new ruleSet', () => {
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
          addresses: {
            optional: [],
            required: ['http.client_ip']
          },
          loaded: ['block_ip'],
          failed: [],
          errors: {}
        }
      })
      assert.deepStrictEqual(waf.knownAddresses, new Set([
        'http.client_ip'
      ]))

      waf.update(rules)
      assert.deepStrictEqual(waf.diagnostics, {
        ruleset_version: '1.3.1',
        rules: {
          addresses: {
            optional: [],
            required: [
              'http.client_ip',
              'server.request.headers.no_cookies',
              'server.response.status',
              'value_attack',
              'key_attack',
              'server.request.body'
            ]
          },
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
      assert.deepStrictEqual(waf.knownAddresses, new Set([
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
      const payload = {
        persistent: {
          'http.client_ip': IP_TO_BLOCK
        }
      }

      const waf = new DDWAF(rules)
      const context = waf.createContext()
      const resultBeforeUpdatingRuleData = context.run(payload, TIMEOUT)
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
      const resultAfterUpdatingRuleData = contextWithRuleData.run(payload, TIMEOUT)

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
                    confidence: '1'
                  }
                }
              ],
              enabled: false
            }
          ]
        }
      ].forEach((testData) => {
        it(`should not collect an attack ${testData.testName}`, () => {
          const payload = {
            persistent: {
              value_attack: 'matchall'
            }
          }
          const waf = new DDWAF(rules)
          const contextToggledOn = waf.createContext()

          const resultToggledOn = contextToggledOn.run(payload, TIMEOUT)

          assert.strictEqual(resultToggledOn.timeout, false)
          assert.strictEqual(resultToggledOn.status, 'match')
          assert(resultToggledOn.events)

          const updateWithRulesOverride = {
            rules_override: testData.rulesOverride
          }

          waf.update(updateWithRulesOverride)
          const contextToggledOff = waf.createContext()

          const resultToggledOff = contextToggledOff.run(payload, TIMEOUT)

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
                    confidence: '1'
                  }
                }
              ],
              on_match: ['block']
            }
          ]
        }
      ].forEach((testData) => {
        it(`should return block action ${testData.testName}`, () => {
          const payload = {
            persistent: {
              value_attack: 'matchall'
            }
          }

          const waf = new DDWAF(rules)
          const monitorContext = waf.createContext()

          const resultMonitor = monitorContext.run(payload, TIMEOUT)

          assert.strictEqual(resultMonitor.timeout, false)
          assert.strictEqual(resultMonitor.status, 'match')
          assert.deepStrictEqual(resultMonitor.actions, [])
          assert(resultMonitor.events)

          const updateWithRulesOverride = {
            rules_override: testData.rulesOverride
          }

          waf.update(updateWithRulesOverride)
          const blockContext = waf.createContext()

          const resultBlock = blockContext.run(payload, TIMEOUT)

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
      persistent: {
        'server.response.status': '404'
      }
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

    const wronArgsError = new Error('Wrong number of arguments, 2 expected')
    assert.throws(() => context.run(), wronArgsError)

    const payloadError = new TypeError('Payload data must be an object')
    assert.throws(() => context.run(null, TIMEOUT), payloadError)

    const objectError = new TypeError('Persistent or ephemeral must be an object')
    assert.throws(() => context.run({}, TIMEOUT), objectError)
    assert.throws(() => context.run({ persistent: '' }, TIMEOUT), objectError)
    assert.throws(() => context.run({ persistent: '', ephemeral: null }, TIMEOUT), objectError)
    assert.throws(() => context.run({ ephemeral: null }, TIMEOUT), objectError)

    const numberError = new TypeError('Timeout argument must be a number')
    assert.throws(() => context.run({ persistent: {}, ephemeral: {} }, ''), numberError)

    const greaterError = new TypeError('Timeout argument must be greater than 0')
    assert.throws(() => context.run({
      persistent: {
        'server.request.headers.no_cookies': 'value_attack'
      }
    }, -1), greaterError)
    assert.throws(() => context.run({
      persistent: {
        'server.request.headers.no_cookies': 'value_attack'
      }
    }, 0), greaterError)
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
        persistent: {
          key_attack: {
            [key]: 'value'
          }
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
      [false, undefined],
      [true, undefined],
      [42, undefined],
      [-42, undefined],
      [42.42, undefined],
      [Infinity, undefined],
      [NaN, undefined],
      [BigInt(42), undefined],
      ['str', 'str'],
      [{ a: '1', b: 2 }, '1'],
      [['a', 2, 'c'], 'a'],
      [/regex/, undefined],
      [function fn () {}, undefined]
    ])

    const waf = new DDWAF(rules)

    for (const [value, expected] of possibleValues) {
      const context = waf.createContext()

      const result = context.run({
        persistent: {
          value_attack: {
            key: value
          }
        }
      }, TIMEOUT)

      assert.strictEqual(result.timeout, false)

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
      persistent: {
        value_attack: {
          password: {
            a: 'sensitive'
          }
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
      persistent: {
        'server.request.headers.no_cookies': {
          header: 'value_attack'
        }
      }
    }, TIMEOUT)

    assert(result)
    assert(result.events)
    assert.strictEqual(result.events[0].rule_matches[0].parameters[0].value, '<Redacted>')
    assert.strictEqual(result.events[0].rule_matches[0].parameters[0].highlight[0], '<Redacted>')
  })

  it('should collect derivatives information when a rule match', () => {
    const waf = new DDWAF(processor)

    const context = waf.createContext()

    assert(waf.diagnostics.processors.addresses.optional.includes('server.request.query'))
    assert(waf.diagnostics.processors.addresses.optional.includes('server.request.body'))
    assert(waf.diagnostics.processors.addresses.required.includes('waf.context.processor'))
    assert(waf.diagnostics.processors.loaded.includes('processor-001'))
    assert.equal(waf.diagnostics.processors.failed.length, 0)

    const result = context.run({
      persistent: {
        'server.request.body': 'value',
        'waf.context.processor': {
          'extract-schema': true
        }
      }
    }, TIMEOUT)

    assert.strictEqual(result.status, 'match')
    assert.deepStrictEqual(result.derivatives, { 'server.request.body.schema': [8] })

    context.dispose()
    assert(context.disposed)

    waf.dispose()
    assert(waf.disposed)
  })

  it('should collect derivatives information when a rule does not match', () => {
    const waf = new DDWAF(processor)
    const context = waf.createContext()

    assert(waf.diagnostics.processors.addresses.optional.includes('server.request.query'))
    assert(waf.diagnostics.processors.addresses.optional.includes('server.request.body'))
    assert(waf.diagnostics.processors.addresses.required.includes('waf.context.processor'))
    assert(waf.diagnostics.processors.loaded.includes('processor-001'))
    assert.equal(waf.diagnostics.processors.failed.length, 0)

    const result = context.run({
      persistent: {
        'server.request.body': '',
        'waf.context.processor': {
          'extract-schema': true
        }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.derivatives, { 'server.request.body.schema': [8] })

    context.dispose()
    assert(context.disposed)

    waf.dispose()
    assert(waf.disposed)
  })

  it('should collect all derivatives types', () => {
    const waf = new DDWAF(processor)
    const context = waf.createContext()

    assert(waf.diagnostics.processors.addresses.optional.includes('server.request.query'))
    assert(waf.diagnostics.processors.addresses.optional.includes('server.request.body'))
    assert(waf.diagnostics.processors.addresses.required.includes('waf.context.processor'))
    assert(waf.diagnostics.processors.loaded.includes('processor-001'))
    assert.equal(waf.diagnostics.processors.failed.length, 0)

    const result = context.run({
      persistent: {
        'server.request.body': {
          null: null,
          integer: 42,
          float: 42.42,
          infinity: Infinity,
          nan: NaN,
          signed: -42,
          boolean: true,
          string: 'string',
          array: [1, 2, 3],
          obj: { key: 'value' },
          undefined: undefined,
          bigint: BigInt(42),
          regex: /regex/,
          function: function fn () {}
        },
        'waf.context.processor': {
          'extract-schema': true
        }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.derivatives, {
      'server.request.body.schema': [
        {
          null: [1],
          boolean: [2],
          float: [16],
          infinity: [16],
          nan: [16],
          integer: [16],
          signed: [16],
          string: [8],
          array: [[[16]], { len: 3 }],
          obj: [{ key: [8] }],
          undefined: [0],
          bigint: [0],
          regex: [{}],
          function: [0]
        }
      ]
    })

    context.dispose()
    assert(context.disposed)

    waf.dispose()
    assert(waf.disposed)
  })

  it('should collect derivatives in two consecutive calls', () => {
    const waf = new DDWAF(processor)
    const context = waf.createContext()

    assert(waf.diagnostics.processors.addresses.optional.includes('server.request.query'))
    assert(waf.diagnostics.processors.addresses.optional.includes('server.request.body'))
    assert(waf.diagnostics.processors.addresses.required.includes('waf.context.processor'))
    assert(waf.diagnostics.processors.loaded.includes('processor-001'))
    assert.equal(waf.diagnostics.processors.failed.length, 0)

    let result = context.run({
      persistent: {
        'server.request.body': ''
      }
    }, TIMEOUT)

    assert.strictEqual(result.derivatives, undefined)

    result = context.run({
      persistent: {
        'server.request.body': '',
        'waf.context.processor': {
          'extract-schema': true
        }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.derivatives, { 'server.request.body.schema': [8] })

    result = context.run({
      persistent: {
        'server.request.query': ''
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.derivatives, { 'server.request.query.schema': [8] })

    context.dispose()
    assert(context.disposed)

    waf.dispose()
    assert(waf.disposed)
  })
})

describe('limit tests', () => {
  it('should ignore elements too far in the objects', () => {
    const waf = new DDWAF(rules)

    const context1 = waf.createContext()
    const result1 = context1.run({
      persistent: {
        'server.response.status': {
          a0: '404'
        }
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
      persistent: {
        'server.response.status': item
      }
    }, TIMEOUT)
    assert(!result2.status)
    assert(!result2.events)
  })

  it('should match a moderately deeply nested object', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()

    const result = context.run({
      persistent: {
        'server.request.headers.no_cookies': createNestedObject(5, { header: 'value_attack' })
      }
    }, TIMEOUT)

    assert.strictEqual(result.status, 'match')
    assert(result.events)
  })

  it('should set as invalid circular property dependency', () => {
    const waf = new DDWAF(processor)
    const context = waf.createContext()
    const payload = {
      key: 'value',
      mail: 'from@domain.com'
    }
    payload.child1 = payload
    payload.child2 = payload
    payload.child3 = payload

    const result = context.run({
      persistent: {
        'server.request.body': payload,
        'waf.context.processor': { 'extract-schema': true }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.derivatives, {
      'server.request.body.schema': [
        {
          mail: [8],
          key: [8],
          child1: [0],
          child2: [0],
          child3: [0]
        }
      ]
    })
  })

  it('should set as invalid circular property dependency in deeper level', () => {
    const waf = new DDWAF(processor)
    const context = waf.createContext()
    const payload = {
      key: 'value',
      mail: 'from@domain.com'
    }
    payload.child1 = { payload }
    payload.child2 = { payload }
    payload.child3 = { payload }

    const result = context.run({
      persistent: {
        'server.request.body': payload,
        'waf.context.processor': { 'extract-schema': true }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.derivatives, {
      'server.request.body.schema': [
        {
          mail: [8],
          key: [8],
          child1: [{ payload: [0] }],
          child2: [{ payload: [0] }],
          child3: [{ payload: [0] }]
        }
      ]
    })
  })

  it('should set as invalid circular array dependency', () => {
    const waf = new DDWAF(processor)
    const context = waf.createContext()
    const payload = [{ key: 'value' }]
    payload.push(payload, payload, payload)

    const result = context.run({
      persistent: {
        'server.request.body': payload,
        'waf.context.processor': { 'extract-schema': true }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.derivatives, {
      'server.request.body.schema': [[[0], [{ key: [8] }]], { len: 4 }]
    })
  })

  it('should set as invalid circular array dependency in deeper levels', () => {
    const waf = new DDWAF(processor)
    const context = waf.createContext()
    const payload = []
    payload.push({ payload })
    payload.push({ payload })
    payload.push({ payload })

    const result = context.run({
      persistent: {
        'server.request.body': payload,
        'waf.context.processor': { 'extract-schema': true }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.derivatives, {
      'server.request.body.schema': [[[{ payload: [0] }]], { len: 3 }]
    })
  })

  it('should not set as invalid same instances in array', () => {
    const waf = new DDWAF(processor)
    const context = waf.createContext()
    const item = {
      key: 'value',
      mail: 'from@domain.com'
    }

    const payload = [item, item, item, item]

    const result = context.run({
      persistent: {
        'server.request.body': payload,
        'waf.context.processor': { 'extract-schema': true }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.derivatives, {
      'server.request.body.schema': [
        [[{ mail: [8], key: [8] }]],
        { len: 4 }
      ]
    })
  })

  it('should not set as invalid same instance in different properties', () => {
    const waf = new DDWAF(processor)
    const context = waf.createContext()
    const prop = {
      key: 'value',
      mail: 'from@domain.com'
    }

    const payload = {}
    payload.prop1 = prop
    payload.prop2 = prop
    payload.prop3 = prop

    const result = context.run({
      persistent: {
        'server.request.body': payload,
        'waf.context.processor': { 'extract-schema': true }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.derivatives, {
      'server.request.body.schema': [
        {
          prop1: [{ mail: [8], key: [8] }],
          prop2: [{ mail: [8], key: [8] }],
          prop3: [{ mail: [8], key: [8] }]
        }
      ]
    })
  })

  it('should not match an extremely deeply nested object', () => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()

    const result = context.run({
      persistent: {
        'server.request.headers.no_cookies': createNestedObject(100, { header: 'value_attack' })
      }
    }, TIMEOUT)

    assert(!result.status)
    assert(!result.events)
  })

  it('should not limit the rules object', () => {
    const waf = new DDWAF(rules)

    // test first item in big rule
    const context1 = waf.createContext()
    const result1 = context1.run({
      persistent: {
        'server.request.body': { a: '.htaccess' }
      }
    }, TIMEOUT)
    assert(result1.status)
    assert(result1.events)

    // test last item in big rule
    const context2 = waf.createContext()
    const result2 = context2.run({
      persistent: {
        'server.request.body': { a: 'yarn.lock' }
      }
    }, TIMEOUT)
    assert(result2.status)
    assert(result2.events)
  })

  it('should use custom toJSON function', () => {
    const waf = new DDWAF(rules)

    const body = { a: 'not_an_attack' }

    // should not match
    const context1 = waf.createContext()
    const result1 = context1.run({
      persistent: {
        'server.request.body': body
      }
    }, TIMEOUT)
    assert(!result1.status)

    body.toJSON = function toJSON () {
      assert(this === body)
      return { a: '.htaccess' }
    }

    // should match
    const context2 = waf.createContext()
    const result2 = context2.run({
      persistent: {
        'server.request.body': body
      }
    }, TIMEOUT)
    assert(result2.status)
    assert(result2.events)
  })

  it('should use custom toJSON function in arrays', () => {
    const waf = new DDWAF(rules)

    const body = ['not_an_attack']

    // should not match
    const context1 = waf.createContext()
    const result1 = context1.run({
      persistent: {
        'server.request.body': body
      }
    }, TIMEOUT)
    assert(!result1.status)

    body.toJSON = function toJSON () {
      assert(this === body)
      return ['.htaccess']
    }

    // should match
    const context2 = waf.createContext()
    const result2 = context2.run({
      persistent: {
        'server.request.body': body
      }
    }, TIMEOUT)
    assert(result2.status)
    assert(result2.events)
  })

  it('should work with array/object changes in toJSON', () => {
    const a1 = ['val']
    a1.toJSON = function () {
      return {
        key0: this[0]
      }
    }
    const body = {
      a: {
        a1
      },
      toJSON: function () {
        return [this.a]
      }
    }

    const waf = new DDWAF(processor)
    const context = waf.createContext()
    const result = context.run({
      persistent: {
        'server.request.body': body,
        'waf.context.processor': {
          'extract-schema': true
        }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.derivatives, {
      'server.request.body.schema': [
        [
          [
            { a1: [{ key0: [8] }] }
          ]
        ],
        { len: 1 }
      ]
    })
  })

  it('should not call nested toJSON functions', () => {
    const body = {
      a: 1,
      b: {
        b: 'b',
        toJSON: function () {
          return { b: 'KO' }
        }
      },
      c: {
        c: 'c',
        toJSON: function () {
          return { c: 'OK' }
        }
      },
      toJSON: function () {
        return this.c
      }
    }

    const waf = new DDWAF(processor)
    const context = waf.createContext()
    const result = context.run({
      persistent: {
        'server.request.body': body,
        'waf.context.processor': {
          'extract-schema': true
        }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.derivatives, {
      'server.request.body.schema': [
        {
          c: [8],
          toJSON: [0]
        }
      ]
    })
  })

  it('should call toJSON functions on children properties', () => {
    const body = {
      a: 1,
      b: {
        b: 2,
        toJSON: function () {
          return { b: 'b-OK' }
        }
      },
      c: {
        c: 3,
        toJSON: function () {
          return { c: 'c-OK' }
        }
      },
      toJSON: function () {
        return {
          a: this.a,
          b: this.b,
          c: this.c
        }
      }
    }

    const waf = new DDWAF(processor)
    const context = waf.createContext()
    const result = context.run({
      persistent: {
        'server.request.body': body,
        'waf.context.processor': {
          'extract-schema': true
        }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.derivatives, {
      'server.request.body.schema': [
        {
          a: [16],
          b: [{ b: [8] }],
          c: [{ c: [8] }]
        }
      ]
    })
  })
})

function createNestedObject (n, obj) {
  if (n > 0) {
    return { a: createNestedObject(n - 1, obj) }
  }

  return obj
}
