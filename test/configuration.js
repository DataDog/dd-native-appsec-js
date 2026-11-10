/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
const { it, describe } = require('mocha')
const assert = require('assert')

const { DDWAF } = require('..')
const rules = require('./rules.json')

const TIMEOUT = 9999e3

function assertAbsent (object, property) {
  assert.strictEqual(
    Object.prototype.hasOwnProperty.call(object, property),
    false,
    `${property} must not be published`
  )
}

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
            const result = context.run({ value_attack: 'attack' }, TIMEOUT)
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
          'server.request.headers.no_cookies': 'value_ATTack'
        }

        const result = context.run(payload, TIMEOUT)

        assert.strictEqual(result.timeout, false)
        assert.strictEqual(result.status, 'match')
        assert(result.events)
        assertAbsent(result, 'actions')
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
        'http.client_ip': IP_TO_BLOCK
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
            value_attack: 'matchall'
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
            value_attack: 'matchall'
          }

          const waf = new DDWAF(rules, 'recommended')
          const monitorContext = waf.createContext()

          const resultMonitor = monitorContext.run(payload, TIMEOUT)

          assert.strictEqual(resultMonitor.timeout, false)
          assert.strictEqual(resultMonitor.status, 'match')
          assertAbsent(resultMonitor, 'actions')
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

describe('DDWAF', () => {
  describe('WAF update', () => {
    describe('Update config', () => {
      const brokenConfig = { rules: [{ name: 'rule_with_missing_id' }] }

      it('should preserve an existing same-path config when an array root is rejected', () => {
        const waf = new DDWAF(rules, 'recommended')
        let context

        try {
          assert.strictEqual(waf.createOrUpdateConfig([], 'recommended'), false)
          assert.deepStrictEqual(waf.configPaths, ['recommended'])

          context = waf.createContext()
          const result = context.run({ 'server.request.headers.no_cookies': 'value_attack' }, TIMEOUT)
          assert.strictEqual(result.status, 'match')
        } finally {
          if (context) context.dispose()
          waf.dispose()
        }
      })

      it('should not keep stale rules active after an invalid same-path replacement removes the builder config', () => {
        const waf = new DDWAF(rules, 'recommended')
        let context

        try {
          assert.strictEqual(waf.createOrUpdateConfig(brokenConfig, 'recommended'), false)
          assert.deepStrictEqual(waf.configPaths, [])

          context = waf.createContext()
          assert.strictEqual(context, null)
        } finally {
          if (context) context.dispose()
          waf.dispose()
        }
      })

      for (const [name, config] of [
        ['an unsupported version', { version: '1.0' }],
        ['a malformed version', { version: 'abc' }],
        ['invalid metadata', { metadata: [] }]
      ]) {
        it(`should restore fallback rules after rejecting ${name} at an existing remote path`, () => {
          const path = 'datadog/2/ASM_DD/rc/config'
          const waf = new DDWAF(rules, path)
          let context

          try {
            assert.strictEqual(waf.createOrUpdateConfig(config, path), false)
            assert.strictEqual(typeof waf.diagnostics.error, 'string')
            assert.deepStrictEqual(waf.configPaths, [])
            assert.strictEqual(waf.createContext(), null)

            assert.strictEqual(waf.createOrUpdateConfig(rules, 'recommended'), true)
            assert.deepStrictEqual(waf.configPaths, ['recommended'])
            context = waf.createContext()
            const result = context.run({ 'server.request.headers.no_cookies': 'value_attack' }, TIMEOUT)
            assert.strictEqual(result.status, 'match')
          } finally {
            if (context) context.dispose()
            waf.dispose()
          }
        })
      }

      it('should discard partially loaded exclusions when a later entry is invalid', () => {
        const waf = new DDWAF(rules, 'recommended')
        let context

        try {
          const config = {
            exclusions: [{ id: 'exclude_attack', rules_target: [{ rule_id: 'value_attack' }] }, 'invalid']
          }
          assert.strictEqual(waf.createOrUpdateConfig(config, 'config/exclusions'), false)
          assert.deepStrictEqual(waf.diagnostics.exclusions, { error: "bad cast, expected 'map', obtained 'string'" })
          assert.deepStrictEqual(waf.configPaths, ['recommended'])

          context = waf.createContext()
          const result = context.run({ 'server.request.headers.no_cookies': 'value_attack' }, TIMEOUT)
          assert.strictEqual(result.status, 'match')
          assert.ok(result.events.some(event => event.rule.id === 'value_attack'))
        } finally {
          if (context) context.dispose()
          waf.dispose()
        }
      })

      it('should not register an unsupported new path alongside a valid config', () => {
        const waf = new DDWAF(rules, 'recommended')
        let context

        try {
          assert.strictEqual(
            waf.createOrUpdateConfig({ version: '1.0' }, 'datadog/2/ASM_DD/rc/config'),
            false
          )
          assert.deepStrictEqual(waf.configPaths, ['recommended'])

          context = waf.createContext()
          const result = context.run({ 'server.request.headers.no_cookies': 'value_attack' }, TIMEOUT)
          assert.strictEqual(result.status, 'match')
        } finally {
          if (context) context.dispose()
          waf.dispose()
        }
      })
    })

    it('should commit an accepted update when publishing diagnostics fails', () => {
      const ipToBlock = '123.123.123.123'
      const waf = new DDWAF(rules, 'recommended')
      let context

      try {
        Object.defineProperty(waf, 'diagnostics', {
          value: waf.diagnostics,
          writable: false,
          enumerable: true,
          configurable: false
        })

        assert.throws(
          () => waf.createOrUpdateConfig({
            rules_data: [{
              id: 'blocked_ips',
              type: 'ip_with_expiration',
              data: [{ value: ipToBlock }]
            }]
          }, 'config/update'),
          Error
        )

        context = waf.createContext()
        const result = context.run({ 'http.client_ip': ipToBlock }, TIMEOUT)
        assert.strictEqual(result.status, 'match')
      } finally {
        if (context) context.dispose()
        waf.dispose()
      }
    })

    describe('live-context handle ownership', () => {
      const ipToBlock = '123.123.123.123'
      const ipPayload = { 'http.client_ip': ipToBlock }
      const attackPayload = { 'server.request.headers.no_cookies': 'value_attack' }
      const ruleDataUpdate = {
        rules_data: [{
          id: 'blocked_ips',
          type: 'ip_with_expiration',
          data: [{ value: ipToBlock }]
        }]
      }

      it('should preserve old context rules while new contexts use a successful replacement handle', () => {
        const waf = new DDWAF(rules, 'recommended')
        let oldContext
        let newContext

        try {
          oldContext = waf.createContext()
          assert.strictEqual(waf.createOrUpdateConfig(ruleDataUpdate, 'config/update'), true)
          newContext = waf.createContext()

          assert.strictEqual(oldContext.run(ipPayload, TIMEOUT).status, undefined)
          assert.strictEqual(newContext.run(ipPayload, TIMEOUT).status, 'match')
        } finally {
          if (newContext) newContext.dispose()
          if (oldContext) oldContext.dispose()
          waf.dispose()
        }
      })

      it('should preserve old context rules after removal or destructive failed replacement', () => {
        const cases = [
          {
            update (waf) {
              assert.strictEqual(waf.removeConfig('recommended'), true)
            },
            disposeWafBeforeOldRun: true
          },
          {
            update (waf) {
              assert.strictEqual(
                waf.createOrUpdateConfig({ rules: [{ name: 'rule_with_missing_id' }] }, 'recommended'),
                false
              )
            },
            disposeWafBeforeOldRun: false
          }
        ]

        for (const testCase of cases) {
          const waf = new DDWAF(rules, 'recommended')
          let oldContext
          let newContext
          try {
            oldContext = waf.createContext()
            testCase.update(waf)
            newContext = waf.createContext()
            assert.strictEqual(newContext, null)

            if (testCase.disposeWafBeforeOldRun) waf.dispose()
            assert.strictEqual(oldContext.run(attackPayload, TIMEOUT).status, 'match')
          } finally {
            if (newContext) newContext.dispose()
            if (oldContext) oldContext.dispose()
            if (!waf.disposed) waf.dispose()
          }
        }
      })

      it('should preserve old context rules when an accepted update fails JavaScript publication', () => {
        const waf = new DDWAF(rules, 'recommended')
        let oldContext
        let newContext

        try {
          oldContext = waf.createContext()
          Object.defineProperty(waf, 'diagnostics', {
            value: waf.diagnostics,
            writable: false,
            enumerable: true,
            configurable: false
          })

          assert.throws(
            () => waf.createOrUpdateConfig(ruleDataUpdate, 'config/update'),
            Error
          )
          newContext = waf.createContext()

          assert.strictEqual(oldContext.run(ipPayload, TIMEOUT).status, undefined)
          assert.strictEqual(newContext.run(ipPayload, TIMEOUT).status, 'match')
        } finally {
          if (newContext) newContext.dispose()
          if (oldContext) oldContext.dispose()
          waf.dispose()
        }
      })
    })
  })

  // Keeping the previous instance when the builder can no longer produce one
  // would leave the removed rules live.
  it('should not keep removed rules active after removing the last config', () => {
    const waf = new DDWAF(rules, 'recommended')
    const payload = { 'server.request.headers.no_cookies': 'value_ATTack' }

    assert.strictEqual(waf.createContext().run(payload, TIMEOUT).status, 'match')
    assert.strictEqual(waf.removeConfig('recommended'), true)
    assert.deepStrictEqual(waf.configPaths, [])
    assert.strictEqual(waf.knownAddresses.size, 0)

    assert.strictEqual(waf.createContext(), null)

    assert.strictEqual(waf.createOrUpdateConfig(rules, 'recommended'), true)
    assert.strictEqual(waf.createContext().run(payload, TIMEOUT).status, 'match')

    waf.dispose()
  })

  // A syntactically valid ruleset with no rules is accepted by the builder but
  // cannot produce an instance. This is the shape that reaches the tracer from
  // Remote Config, so it must be reported rather than left matching stale rules.
  it('should report no context for an accepted but ruleless config', () => {
    const waf = new DDWAF(rules, 'recommended')
    const payload = { 'server.request.headers.no_cookies': 'value_ATTack' }

    assert.strictEqual(waf.removeConfig('recommended'), true)
    assert.strictEqual(waf.createOrUpdateConfig({ version: '2.2', rules: [] }, 'datadog/2/ASM_DD/rc/config'), true)

    assert.strictEqual(waf.knownAddresses.size, 0)
    assert.strictEqual(waf.createContext(), null)

    assert.strictEqual(waf.createOrUpdateConfig(rules, 'recommended'), true)
    assert.strictEqual(waf.createContext().run(payload, TIMEOUT).status, 'match')

    waf.dispose()
  })

  it('should reject reserved and empty config paths', () => {
    const reserved = '::/native-appsec/obfuscator'

    assert.throws(() => new DDWAF(rules, ''), new TypeError('Config path must not be empty'))
    assert.throws(() => new DDWAF(rules, reserved), new Error('Config path is reserved'))

    const waf = new DDWAF(rules, 'recommended', { obfuscatorKeyRegex: 'password' })

    assert.throws(() => waf.createOrUpdateConfig({}, ''), new TypeError('Config path must not be empty'))
    assert.throws(() => waf.removeConfig(''), new TypeError('Config path must not be empty'))
    assert.throws(() => waf.createOrUpdateConfig({}, reserved), new Error('Config path is reserved'))
    assert.throws(() => waf.removeConfig(reserved), new Error('Config path is reserved'))

    assert.deepStrictEqual(waf.configPaths, ['recommended'])

    waf.dispose()
  })
})
