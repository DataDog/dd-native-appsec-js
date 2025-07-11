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
    const waf = new DDWAF(rules, 'recommended')

    assert.deepStrictEqual(waf.diagnostics, {
      ruleset_version: '1.3.1',
      actions: {
        errors: {},
        warnings: {},
        failed: [],
        loaded: [
          'customblock'
        ],
        skipped: []
      },
      rules: {
        loaded: [
          'block_ip',
          'value_attack',
          'key_attack',
          'nfd-000-001',
          'value_matchall',
          'key_matchall',
          'custom_action_rule',
          'test-marshalling',
          'long_rule'
        ],
        skipped: [],
        failed: ['invalid_1', 'invalid_2', 'invalid_3'],
        errors: {
          'missing key \'regex\'': [
            'invalid_1'
          ],
          'invalid regular expression: *': [
            'invalid_2',
            'invalid_3'
          ]
        },
        warnings: {}
      }
    })
  })

  it('should have knownAddresses', () => {
    const waf = new DDWAF(rules, 'recommended')

    assert.deepStrictEqual(waf.knownAddresses, new Set([
      'http.client_ip',
      'server.request.headers.no_cookies',
      'server.response.status',
      'value_attack',
      'key_attack',
      'server.request.body',
      'custom_value_attack'
    ]))
  })

  it('should have knownActions', () => {
    const waf = new DDWAF(rules, 'recommended')

    assert.deepStrictEqual(waf.knownActions, new Set([
      'block_request'
    ]))
  })

  it('should collect an attack and cleanup everything', () => {
    const waf = new DDWAF(rules, 'recommended')
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
    assert.deepStrictEqual(result.actions, {})
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
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()
    let result = context.run({
      ephemeral: {
        'server.request.headers.no_cookies': 'value_ATTack'
      }
    }, TIMEOUT)

    assert.strictEqual(result.timeout, false)
    assert.strictEqual(result.status, 'match')
    assert.strictEqual(result.events[0].rule_matches[0].parameters[0].value, 'value_attack')
    assert.deepStrictEqual(result.actions, {})
    assert.deepStrictEqual(result.metrics, {})

    result = context.run({
      ephemeral: {
        'server.request.headers.no_cookies': 'other_attack'
      }
    }, TIMEOUT)

    assert.strictEqual(result.timeout, false)
    assert.strictEqual(result.status, 'match')
    assert.strictEqual(result.events[0].rule_matches[0].parameters[0].value, 'other_attack')
    assert.deepStrictEqual(result.actions, {})
    assert.deepStrictEqual(result.metrics, {})

    context.dispose()

    waf.dispose()
  })

  describe('WAF update', () => {
    describe('Update config', () => {
      it('should throw an error when updating configuration on a disposed WAF instance', () => {
        const waf = new DDWAF(rules, 'recommended')
        waf.dispose()
        assert.throws(
          () => waf.createOrUpdateConfig(rules, 'config/update'),
          new Error('Could not update a disposed WAF instance'))
      })

      it('should throw an error when updating configuration with no arguments', () => {
        const waf = new DDWAF(rules, 'recommended')
        assert.throws(() => waf.createOrUpdateConfig(), new Error('Wrong number of arguments, expected at least 2'))
      })

      it('should throw an error when updating configuration with just one argument', () => {
        const waf = new DDWAF(rules, 'recommended')
        assert.throws(() => waf.createOrUpdateConfig({}), new Error('Wrong number of arguments, expected at least 2'))
      })

      it('should throw a type error when updating configuration with invalid arguments', () => {
        const waf = new DDWAF(rules, 'recommended')
        assert.throws(
          () => waf.createOrUpdateConfig('string', 'config/update'),
          new TypeError('First argument must be an object')
        )
        assert.strictEqual(waf.disposed, false)
      })

      it('should return false when updating configuration with invalid configuration', () => {
        const waf = new DDWAF(rules, 'recommended')
        assert.strictEqual(waf.createOrUpdateConfig({}, 'config/update'), false)
        assert.strictEqual(waf.disposed, false)
      })

      it('should keep functional handle after updating an invalid configuration', () => {
        const waf = new DDWAF(rules, 'recommended')
        waf.createOrUpdateConfig({}, 'config/update')

        assert(!waf.disposed)

        const context = waf.createContext()
        const payload = {
          persistent: {
            'server.request.headers.no_cookies': 'value_ATTack'
          }
        }

        const result = context.run(payload, TIMEOUT)

        assert.strictEqual(result.timeout, false)
        assert.strictEqual(result.status, 'match')
        assert(result.events)
        assert.deepStrictEqual(result.actions, {})
        assert(!context.disposed)
      })

      it('should return true when updating configuration', () => {
        const waf = new DDWAF(rules, 'recommended')
        const newConfig = {
          version: '2.2',
          metadata: {
            rules_version: '1.3.0'
          },
          actions: [{
            id: 'customredirect',
            type: 'redirect_request',
            parameters: {
              status_code: '301',
              location: '/'
            }
          }],
          rules: [{
            id: 'block_ip_original',
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
              'customredirect'
            ]
          }]
        }
        assert.strictEqual(waf.createOrUpdateConfig(newConfig, 'config/update'), true)
      })
    })

    describe('Remove config', () => {
      it('should throw an error when removing a configuration on a disposed WAF instance', () => {
        const waf = new DDWAF(rules, 'recommended')
        waf.dispose()
        assert.throws(
          () => waf.removeConfig('config/update'),
          new Error('Could not update a disposed WAF instance'))
      })

      it('should throw an error when removing a configuration with no arguments', () => {
        const waf = new DDWAF(rules, 'recommended')
        assert.throws(() => waf.removeConfig(), new Error('Wrong number of arguments, expected at least 1'))
      })

      it('should throw a type error when removing a configuration with invalid arguments', () => {
        const waf = new DDWAF(rules, 'recommended')
        assert.throws(
          () => waf.removeConfig(null),
          new TypeError('First argument must be a string')
        )
      })

      it('should return true when removing an existing configuration', () => {
        const waf = new DDWAF(rules, 'recommended')
        assert.strictEqual(waf.removeConfig('recommended'), true)
        assert.strictEqual(waf.configPaths.length, 0)
      })

      it('should return false when removing a non-existing configuration', () => {
        const waf = new DDWAF(rules, 'recommended')
        assert.strictEqual(waf.removeConfig('config/update'), false)
        assert.ok(
          waf.configPaths.includes('recommended') &&
          waf.configPaths.length === 1
        )
      })
    })

    describe('Config paths', () => {
      it('should have no loaded configuration paths on WAF disposed instance', () => {
        const waf = new DDWAF(rules, 'recommended')
        waf.dispose()
        assert.strictEqual(waf.configPaths.length, 0)
      })

      it('should have loaded configuration paths', () => {
        const waf = new DDWAF(rules, 'recommended')
        const newConfig = {
          rules: [{
            id: 'block_ip_original',
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
              'customredirect'
            ]
          }]
        }
        waf.createOrUpdateConfig(newConfig, 'config/update')
        assert.ok(
          waf.configPaths.includes('recommended') &&
          waf.configPaths.includes('config/update') &&
          waf.configPaths.length === 2
        )
      })
    })

    it('should update diagnostics, knownAddresses, and knownActions when updating an instance with new ruleSet', () => {
      const waf = new DDWAF({
        version: '2.2',
        metadata: {
          rules_version: '1.3.0'
        },
        actions: [{
          id: 'customredirect',
          type: 'redirect_request',
          parameters: {
            status_code: '301',
            location: '/'
          }
        }],
        rules: [{
          id: 'block_ip_original',
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
            'customredirect'
          ]
        }]
      }, 'new_ruleset')

      assert.deepStrictEqual(waf.diagnostics, {
        ruleset_version: '1.3.0',
        actions: {
          errors: {},
          warnings: {},
          failed: [],
          loaded: [
            'customredirect'
          ],
          skipped: []
        },
        rules: {
          loaded: ['block_ip_original'],
          failed: [],
          skipped: [],
          errors: {},
          warnings: {}
        }
      })
      assert.deepStrictEqual(waf.knownAddresses, new Set([
        'http.client_ip'
      ]))
      assert.deepStrictEqual(waf.knownActions, new Set([
        'redirect_request'
      ]))

      waf.createOrUpdateConfig(rules, 'config/update')
      assert.deepStrictEqual(waf.diagnostics, {
        ruleset_version: '1.3.1',
        actions: {
          errors: {},
          warnings: {},
          failed: [],
          loaded: [
            'customblock'
          ],
          skipped: []
        },
        rules: {
          loaded: [
            'block_ip',
            'value_attack',
            'key_attack',
            'nfd-000-001',
            'value_matchall',
            'key_matchall',
            'custom_action_rule',
            'test-marshalling',
            'long_rule'
          ],
          failed: ['invalid_1', 'invalid_2', 'invalid_3'],
          skipped: [],
          errors: {
            'missing key \'regex\'': [
              'invalid_1'
            ],
            'invalid regular expression: *': [
              'invalid_2',
              'invalid_3'
            ]
          },
          warnings: {}
        }
      })
      assert.deepStrictEqual(waf.knownAddresses, new Set([
        'http.client_ip',
        'server.request.headers.no_cookies',
        'server.response.status',
        'value_attack',
        'key_attack',
        'server.request.body',
        'custom_value_attack'
      ]))
      assert.deepStrictEqual(waf.knownActions, new Set([
        'block_request',
        'redirect_request'
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

      const waf = new DDWAF(rules, 'recommended')
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

      waf.createOrUpdateConfig(updateWithRulesData, 'config/update')
      const contextWithRuleData = waf.createContext()
      const resultAfterUpdatingRuleData = contextWithRuleData.run(payload, TIMEOUT)

      assert.strictEqual(resultAfterUpdatingRuleData.timeout, false)
      assert.strictEqual(resultAfterUpdatingRuleData.status, 'match')
      assert(resultAfterUpdatingRuleData.events)
      assert.deepStrictEqual(resultAfterUpdatingRuleData.actions, {
        block_request: {
          grpc_status_code: '10',
          status_code: '403',
          type: 'auto'
        }
      })
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
          const waf = new DDWAF(rules, 'recommended')
          const contextToggledOn = waf.createContext()

          const resultToggledOn = contextToggledOn.run(payload, TIMEOUT)

          assert.strictEqual(resultToggledOn.timeout, false)
          assert.strictEqual(resultToggledOn.status, 'match')
          assert(resultToggledOn.events)

          const updateWithRulesOverride = {
            rules_override: testData.rulesOverride
          }

          waf.createOrUpdateConfig(updateWithRulesOverride, 'config/update')
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

          const waf = new DDWAF(rules, 'recommended')
          const monitorContext = waf.createContext()

          const resultMonitor = monitorContext.run(payload, TIMEOUT)

          assert.strictEqual(resultMonitor.timeout, false)
          assert.strictEqual(resultMonitor.status, 'match')
          assert.deepStrictEqual(resultMonitor.actions, {})
          assert(resultMonitor.events)

          const updateWithRulesOverride = {
            rules_override: testData.rulesOverride
          }

          waf.createOrUpdateConfig(updateWithRulesOverride, 'config/update')
          const blockContext = waf.createContext()

          const resultBlock = blockContext.run(payload, TIMEOUT)

          assert.strictEqual(resultBlock.timeout, false)
          assert.strictEqual(resultBlock.status, 'match')
          assert.deepStrictEqual(resultBlock.actions, {
            block_request: {
              grpc_status_code: '10',
              status_code: '403',
              type: 'auto'
            }
          })
        })
      })
    })
  })

  it('should support case_sensitive', () => {
    const waf = new DDWAF(rules, 'recommended')
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
    assert.throws(() => new DDWAF({}, 'empty_rules'), new Error('Invalid rules'))
    assert.throws(() => new DDWAF('', 'non_object_rules'), new TypeError('First argument must be an object'))
  })

  it('should refuse to run with bad signatures', () => {
    const waf = new DDWAF(rules, 'recommended')
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

    const waf = new DDWAF(rules, 'recommended')

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

    const waf = new DDWAF(rules, 'recommended')

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
    const waf = new DDWAF(rules, 'recommended', {
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
    const waf = new DDWAF(rules, 'recommended', {
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

  it('should collect result attributes information when a rule match', () => {
    const waf = new DDWAF(processor, 'processor_rules')

    const context = waf.createContext()

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
    assert.deepStrictEqual(result.attributes, { 'server.request.body.schema': [8] })

    context.dispose()
    assert(context.disposed)

    waf.dispose()
    assert(waf.disposed)
  })

  it('should collect result attributes information when a rule does not match', () => {
    const waf = new DDWAF(processor, 'processor_rules')
    const context = waf.createContext()

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

    assert.deepStrictEqual(result.attributes, { 'server.request.body.schema': [8] })

    context.dispose()
    assert(context.disposed)

    waf.dispose()
    assert(waf.disposed)
  })

  it('should collect all result attributes types', () => {
    const waf = new DDWAF(processor, 'processor_rules')
    const context = waf.createContext()

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

    assert.deepStrictEqual(result.attributes, {
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

  it('should collect result attributes in two consecutive calls', () => {
    const waf = new DDWAF(processor, 'processor_rules')
    const context = waf.createContext()

    assert(waf.diagnostics.processors.loaded.includes('processor-001'))
    assert.equal(waf.diagnostics.processors.failed.length, 0)

    let result = context.run({
      persistent: {
        'server.request.body': ''
      }
    }, TIMEOUT)

    assert.strictEqual(result.attributes, undefined)

    result = context.run({
      persistent: {
        'server.request.body': '',
        'waf.context.processor': {
          'extract-schema': true
        }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.attributes, { 'server.request.body.schema': [8] })

    result = context.run({
      persistent: {
        'server.request.query': ''
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.attributes, { 'server.request.query.schema': [8] })

    context.dispose()
    assert(context.disposed)

    waf.dispose()
    assert(waf.disposed)
  })

  it('should include keep field in result object', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    // Non-match result
    let result = context.run({
      persistent: {
        'server.request.headers.no_cookies': 'normal_value'
      }
    }, TIMEOUT)

    assert.strictEqual(result.timeout, false)
    assert.strictEqual(typeof result.keep, 'boolean')
    assert.strictEqual(result.keep, false)

    // Match result
    result = context.run({
      persistent: {
        'server.request.headers.no_cookies': 'value_attack'
      }
    }, TIMEOUT)

    assert.strictEqual(result.timeout, false)
    assert.strictEqual(result.status, 'match')
    assert.strictEqual(typeof result.keep, 'boolean')
    assert.strictEqual(result.keep, true)

    context.dispose()
    waf.dispose()
  })

  it('should perform correct marshalling of ddwaf_object', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()
    const result = context.run({
      persistent: {
        'server.request.headers.no_cookies': 'marshalling'
      }
    }, TIMEOUT)

    assert.strictEqual(result.timeout, false)
    assert.strictEqual(result.status, 'match')
    assert.strictEqual(result.keep, true)
    assert.strictEqual(result.attributes['_dd.appsec.trace.integer'], 662607015)
    assert.strictEqual(result.attributes['_dd.appsec.trace.negative_integer'], -662607015)
    assert.strictEqual(result.attributes['_dd.appsec.trace.float'], 2.71828)
    assert.strictEqual(result.attributes['_dd.appsec.trace.negative_float'], -3.14159)
    assert.strictEqual(result.attributes['_dd.appsec.trace.bool'], true)
    assert.strictEqual(
      result.attributes['_dd.appsec.trace.string'],
      'It was a bright cold day in April, and the clocks were striking thirteen.'
    )

    context.dispose()
    waf.dispose()
  })

  describe('Action semantics', () => {
    it('should support action definition in initialisation', () => {
      const waf = new DDWAF(rules, 'recommended')
      const context = waf.createContext()

      const result = context.run({
        persistent: {
          custom_value_attack: 'match'
        }
      }, TIMEOUT)

      assert.strictEqual(result.timeout, false)
      assert.strictEqual(result.status, 'match')
      assert(result.events)
      assert.deepStrictEqual(result.actions, {
        block_request: {
          grpc_status_code: '10',
          status_code: '418',
          type: 'auto'
        }
      })
      assert.deepStrictEqual(result.metrics, {})
    })

    it('should support action definition in update', () => {
      const waf = new DDWAF(rules, 'recommended')

      const updatedRules = Object.assign({}, rules)
      updatedRules.actions = [{
        id: 'customblock',
        type: 'block_request',
        parameters: {
          status_code: '404',
          grpc_status_code: '10',
          type: 'auto'
        }
      }]

      waf.removeConfig('recommended')
      waf.createOrUpdateConfig(updatedRules, 'recommended_action_modified')

      const context = waf.createContext()
      const resultWithUpdatedAction = context.run({
        persistent: {
          custom_value_attack: 'match'
        }
      }, TIMEOUT)

      assert.strictEqual(resultWithUpdatedAction.timeout, false)
      assert.strictEqual(resultWithUpdatedAction.status, 'match')
      assert(resultWithUpdatedAction.events)
      assert.deepStrictEqual(resultWithUpdatedAction.actions, {
        block_request: {
          grpc_status_code: '10',
          status_code: '404',
          type: 'auto'
        }
      })
      assert.deepStrictEqual(resultWithUpdatedAction.metrics, {})
    })
  })
})

describe('limit tests', () => {
  it('should ignore elements too far in the objects', () => {
    const waf = new DDWAF(rules, 'recommended')

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
    const length = 1000
    for (let i = 0; i < length; ++i) {
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
    assert.strictEqual(result2.metrics.maxTruncatedContainerSize, length)
  })

  it('should match a moderately deeply nested object', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    const result = context.run({
      persistent: {
        'server.request.headers.no_cookies': createNestedObject(5, { header: 'value_attack' })
      }
    }, TIMEOUT)

    assert.strictEqual(result.status, 'match')
    assert.deepStrictEqual(result.metrics, {})
    assert(result.events)
  })

  it('should set as invalid circular property dependency', () => {
    const waf = new DDWAF(processor, 'processor_rules')
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

    assert.deepStrictEqual(result.attributes, {
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
    const waf = new DDWAF(processor, 'processor_rules')
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

    assert.deepStrictEqual(result.attributes, {
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
    const waf = new DDWAF(processor, 'processor_rules')
    const context = waf.createContext()
    const payload = []
    payload.push(payload, payload, payload)

    const result = context.run({
      persistent: {
        'server.request.body': payload,
        'waf.context.processor': { 'extract-schema': true }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.attributes, {
      'server.request.body.schema': [[[0]], { len: 3 }]
    })
  })

  it('should set as invalid circular array dependency in deeper levels', () => {
    const waf = new DDWAF(processor, 'processor_rules')
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

    assert.deepStrictEqual(result.attributes, {
      'server.request.body.schema': [[[{ payload: [0] }]], { len: 3 }]
    })
  })

  it('should not set as invalid same instances in array', () => {
    const waf = new DDWAF(processor, 'processor_rules')
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

    assert.deepStrictEqual(result.attributes, {
      'server.request.body.schema': [
        [[{ mail: [8], key: [8] }]],
        { len: 4 }
      ]
    })
  })

  it('should not set as invalid same instance in different properties', () => {
    const waf = new DDWAF(processor, 'processor_rules')
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

    assert.deepStrictEqual(result.attributes, {
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
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    const result = context.run({
      persistent: {
        'server.request.headers.no_cookies': createNestedObject(100, { header: 'value_attack' })
      }
    }, TIMEOUT)

    assert(!result.status)
    assert(!result.events)
    assert.strictEqual(result.metrics.maxTruncatedContainerDepth, 20)
  })

  it('should not limit the rules object', () => {
    const waf = new DDWAF(rules, 'recommended')

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
    const waf = new DDWAF(rules, 'recommended')

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
    const waf = new DDWAF(rules, 'recommended')

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

    const waf = new DDWAF(processor, 'processor_rules')
    const context = waf.createContext()
    const result = context.run({
      persistent: {
        'server.request.body': body,
        'waf.context.processor': {
          'extract-schema': true
        }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.attributes, {
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

    const waf = new DDWAF(processor, 'processor_rules')
    const context = waf.createContext()
    const result = context.run({
      persistent: {
        'server.request.body': body,
        'waf.context.processor': {
          'extract-schema': true
        }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.attributes, {
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

    const waf = new DDWAF(processor, 'processor_rules')
    const context = waf.createContext()
    const result = context.run({
      persistent: {
        'server.request.body': body,
        'waf.context.processor': {
          'extract-schema': true
        }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.attributes, {
      'server.request.body.schema': [
        {
          a: [16],
          b: [{ b: [8] }],
          c: [{ c: [8] }]
        }
      ]
    })
  })

  it('should handle toJSON errors gracefully with invalid fallback', () => {
    const body = {
      a: {
        toJSON: function () {
          throw new Error('error')
        }
      },
      c: 'c'
    }

    const waf = new DDWAF(processor, 'processor_rules')
    const context = waf.createContext()
    const result = context.run({
      persistent: {
        'server.request.body': body,
        'waf.context.processor': {
          'extract-schema': true
        }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.attributes, {
      'server.request.body.schema': [
        {
          a: [0],
          c: [8]
        }
      ]
    })
  })

  it('should truncate string values exceeding maximum length', () => {
    const waf = new DDWAF(rules, 'recommended')

    const context1 = waf.createContext()
    const result1 = context1.run({
      persistent: {
        'server.response.status': '404'
      }
    }, TIMEOUT)
    assert.strictEqual(result1.status, 'match')
    assert(result1.events)

    const longValue = 'a'.repeat(5000)

    const context2 = waf.createContext()
    const result2 = context2.run({
      persistent: {
        'server.response.status': longValue,
        'server.request.body': { a: longValue + 'a' }
      }
    }, TIMEOUT)

    assert(!result2.status)
    assert(!result2.events)
    assert.strictEqual(result2.metrics.maxTruncatedString, 5001)
  })

  it('should handle multiple truncations in complex nested structure', () => {
    const waf = new DDWAF(rules, 'recommended')

    const longValue1 = 'a'.repeat(5000)
    const longValue2 = 'b'.repeat(6000)
    const longValue3 = 'b'.repeat(7000)

    const largeObject1 = {}
    const largeObject2 = {}
    const length1 = 300
    const length2 = 400
    for (let i = 0; i < length1; ++i) {
      largeObject1[`key${i}`] = `value${i}`
    }
    for (let i = 0; i < length2; ++i) {
      largeObject2[`item${i}`] = `data${i}`
    }

    const deepObject1 = createNestedObject(25, { value: longValue1 })
    const deepObject2 = createNestedObject(30, { data: longValue3 })

    const context = waf.createContext()
    const result = context.run({
      persistent: {
        'server.request.body': {
          deep1: deepObject1,
          large1: largeObject1,
          deep2: deepObject2,
          large2: largeObject2,
          str1: longValue1,
          str2: longValue2
        }
      }
    }, TIMEOUT)

    assert(!result.status)
    assert(!result.events)
    assert.strictEqual(result.metrics.maxTruncatedString, 6000)
    assert.strictEqual(result.metrics.maxTruncatedContainerSize, 400)
    assert.strictEqual(result.metrics.maxTruncatedContainerDepth, 20)
  })
})

describe('Handle errors', () => {
  it('should handle invalid arguments number', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    try {
      context.run({
        persistent: {}
      })
    } catch (e) {
      assert.strictEqual(e.message, 'Wrong number of arguments, 2 expected')
    }
  })

  it('should handle invalid timeout arguments', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    try {
      context.run({
        persistent: {}
      }, 'TIMEOUT')
    } catch (e) {
      assert.strictEqual(e.message, 'Timeout argument must be a number')
    }

    try {
      context.run({
        persistent: {}
      }, 0)
    } catch (e) {
      assert.strictEqual(e.message, 'Timeout argument must be greater than 0')
    }
  })

  it('should handle invalid arguments', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    try {
      context.run({
        persistent: 'invalid_object'
      }, TIMEOUT)
    } catch (e) {
      assert.strictEqual(e.message, 'Persistent or ephemeral must be an object')
    }
  })
})

function createNestedObject (n, obj) {
  if (n > 0) {
    return { a: createNestedObject(n - 1, obj) }
  }

  return obj
}
