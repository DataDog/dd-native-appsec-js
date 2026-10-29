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
