/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
const { it, describe } = require('mocha')
const assert = require('assert')

const { DDWAF } = require('..')
const rules = require('./rules.json')

const TIMEOUT = 9999e3

describe('DDWAF', () => {
  describe('WAF update', () => {
    describe('Update config', () => {
      const brokenConfig = { rules: [{ name: 'rule_with_missing_id' }] }

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
        assert.strictEqual(waf.createOrUpdateConfig(brokenConfig, 'config/update'), false)
        assert.strictEqual(waf.disposed, false)
      })

      for (const section of ['rules', 'custom_rules']) {
        it(`should preserve diagnostics and recover after repeated rejected ${section} updates`, () => {
          const waf = new DDWAF(rules, 'recommended')
          const knownAddresses = new Set(waf.knownAddresses)
          const knownActions = new Set(waf.knownActions)
          const invalidRule = rules.rules.find(rule => rule.id === 'invalid_2')
          let context

          try {
            for (let i = 0; i < 3; i++) {
              const id = `invalid_update_${i}`
              const config = { [section]: [{ ...invalidRule, id }] }

              assert.strictEqual(waf.createOrUpdateConfig(config, 'config/update'), false)
              assert.deepStrictEqual(waf.diagnostics[section], {
                loaded: [],
                failed: [id],
                skipped: [],
                errors: { 'invalid regular expression: *': [id] },
                warnings: {}
              })
              assert.deepStrictEqual(waf.configPaths, ['recommended'])
              assert.deepStrictEqual(waf.knownAddresses, knownAddresses)
              assert.deepStrictEqual(waf.knownActions, knownActions)
              assert.strictEqual(waf.disposed, false)
            }

            context = waf.createContext()
            const result = context.run({ persistent: { value_attack: 'attack' } }, TIMEOUT)
            assert.strictEqual(result.timeout, false)
            assert.strictEqual(result.status, 'match')

            const validRule = { ...rules.rules.find(rule => rule.id === 'value_matchall'), id: 'valid_update' }
            assert.strictEqual(waf.createOrUpdateConfig({ rules: [validRule] }, 'config/update'), true)
            assert.ok(waf.configPaths.includes('config/update'))
            assert.deepStrictEqual(waf.diagnostics.rules.loaded, ['valid_update'])
          } finally {
            if (context) context.dispose()
            waf.dispose()
          }
        })
      }

      it('should keep functional handle after updating an invalid configuration', () => {
        const waf = new DDWAF(rules, 'recommended')
        waf.createOrUpdateConfig(brokenConfig, 'config/update')

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
          security_response_id: resultAfterUpdatingRuleData?.actions?.block_request?.security_response_id,
          grpc_status_code: 10,
          status_code: 403,
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
              security_response_id: resultBlock?.actions?.block_request?.security_response_id,
              grpc_status_code: 10,
              status_code: 403,
              type: 'auto'
            }
          })
        })
      })
    })
  })
})
