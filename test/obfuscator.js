/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
const { it, describe } = require('mocha')
const assert = require('assert')
const { DDWAF } = require('..')
const rules = require('./rules.json')
const matchedValue = require('./helpers/matched_value')

const TIMEOUT = 9999e3

describe('DDWAF', () => {
  it('should not obfuscate a dimension that was not configured', () => {
    const sensitiveKey = {
      value_attack: {
        password: {
          a: 'sensitive'
        }
      }
    }

    const matchedValue = (config) => {
      const waf = config === undefined
        ? new DDWAF(rules, 'recommended')
        : new DDWAF(rules, 'recommended', config)
      const context = waf.createContext()
      const result = context.run(sensitiveKey, TIMEOUT)
      const value = result.events[0].rule_matches[0].parameters[0].value
      context.dispose()
      waf.dispose()
      return value
    }

    assert.strictEqual(matchedValue(undefined), 'sensitive')
    assert.strictEqual(matchedValue({ obfuscatorValueRegex: 'zzz_no_match' }), 'sensitive')
    assert.strictEqual(matchedValue({ obfuscatorKeyRegex: '', obfuscatorValueRegex: '' }), 'sensitive')
    assert.strictEqual(matchedValue({ obfuscatorKeyRegex: 'password' }), '<Redacted>')
  })

  describe('obfuscator regex validation', () => {
    const keyPayload = {
      value_attack: {
        password: {
          a: 'sensitive'
        }
      }
    }
    const valuePayload = {
      'server.request.headers.no_cookies': {
        header: 'value_attack'
      }
    }

    const assertConstructorRejects = (option, pattern) => {
      let waf
      try {
        assert.throws(() => {
          waf = new DDWAF(rules, 'recommended', { [option]: pattern })
        })
      } finally {
        if (waf && !waf.disposed) waf.dispose()
      }
    }

    const assertDocumentRejects = (obfuscator) => {
      let waf
      try {
        assert.throws(() => {
          waf = new DDWAF({ ...rules, obfuscator }, 'recommended')
        })
      } finally {
        if (waf && !waf.disposed) waf.dispose()
      }
    }

    it('should reject malformed constructor obfuscator regexes in both dimensions', () => {
      assertConstructorRejects('obfuscatorKeyRegex', '[')
      assertConstructorRejects('obfuscatorValueRegex', '[')
    })

    it('should reject constructor obfuscator regexes unsupported by RE2', () => {
      assertConstructorRejects('obfuscatorKeyRegex', '(?<=a)b')
      assertConstructorRejects('obfuscatorValueRegex', '(?<=a)b')
    })

    it('should reject constructor obfuscator document regexes in both dimensions', () => {
      for (const field of ['key_regex', 'value_regex']) {
        for (const pattern of ['[', '(?<=a)b']) {
          let waf
          try {
            assert.throws(() => {
              waf = new DDWAF({
                ...rules,
                obfuscator: { [field]: pattern }
              }, 'recommended')
            })
          } finally {
            if (waf && !waf.disposed) waf.dispose()
          }
        }
      }
    })

    it('should reject malformed constructor obfuscator document shapes', () => {
      assertDocumentRejects(null)
      assertDocumentRejects(42)
      assertDocumentRejects({ key_regex: 42, value_regex: '' })
      assertDocumentRejects({ key_regex: '', value_regex: 42 })
    })

    it('should ignore inherited constructor obfuscator options', () => {
      const options = Object.create({
        obfuscatorKeyRegex: '[',
        obfuscatorValueRegex: '(?<=a)b'
      })
      let waf

      try {
        waf = new DDWAF(rules, 'recommended', options)
        assert.strictEqual(matchedValue(waf, keyPayload), 'sensitive')
        assert.strictEqual(matchedValue(waf, valuePayload), 'value_attack')
      } finally {
        if (waf && !waf.disposed) waf.dispose()
      }
    })

    it('should preserve absent and empty obfuscator dimension compatibility', () => {
      const outputs = (options) => {
        const waf = options === undefined
          ? new DDWAF(rules, 'recommended')
          : new DDWAF(rules, 'recommended', options)
        try {
          return {
            key: matchedValue(waf, keyPayload),
            value: matchedValue(waf, valuePayload)
          }
        } finally {
          waf.dispose()
        }
      }

      assert.deepStrictEqual(outputs(undefined), { key: 'sensitive', value: 'value_attack' })
      assert.deepStrictEqual(outputs({ obfuscatorValueRegex: 'zzz_no_match' }), {
        key: 'sensitive',
        value: 'value_attack'
      })
      assert.deepStrictEqual(outputs({ obfuscatorKeyRegex: 'zzz_no_match' }), {
        key: 'sensitive',
        value: 'value_attack'
      })
      assert.deepStrictEqual(outputs({ obfuscatorKeyRegex: 'password', obfuscatorValueRegex: '' }), {
        key: '<Redacted>',
        value: 'value_attack'
      })
      assert.deepStrictEqual(outputs({ obfuscatorKeyRegex: '', obfuscatorValueRegex: 'value_attack' }), {
        key: 'sensitive',
        value: '<Redacted>'
      })
      assert.deepStrictEqual(outputs({ obfuscatorKeyRegex: '', obfuscatorValueRegex: '' }), {
        key: 'sensitive',
        value: 'value_attack'
      })
    })

    it('should apply valid public runtime obfuscator updates in both dimensions', () => {
      const cases = [
        {
          config: { key_regex: 'password', value_regex: '' },
          payload: keyPayload,
          before: 'sensitive'
        },
        {
          config: { key_regex: '', value_regex: 'value_attack' },
          payload: valuePayload,
          before: 'value_attack'
        }
      ]

      for (const testCase of cases) {
        const waf = new DDWAF(rules, 'recommended')
        try {
          assert.strictEqual(matchedValue(waf, testCase.payload), testCase.before)
          assert.strictEqual(
            waf.createOrUpdateConfig({ obfuscator: testCase.config }, 'public/obfuscator'),
            true
          )
          assert.strictEqual(matchedValue(waf, testCase.payload), '<Redacted>')
        } finally {
          waf.dispose()
        }
      }
    })

    it('should reject malformed public runtime obfuscator updates without weakening active protection', () => {
      const cases = [
        {
          field: 'key_regex',
          config: { key_regex: 'password', value_regex: '' },
          payload: keyPayload
        },
        {
          field: 'value_regex',
          config: { key_regex: '', value_regex: 'value_attack' },
          payload: valuePayload
        }
      ]

      for (const testCase of cases) {
        for (const pattern of ['[', '(?<=a)b']) {
          const waf = new DDWAF(rules, 'recommended')
          try {
            assert.strictEqual(
              waf.createOrUpdateConfig({ obfuscator: testCase.config }, 'public/obfuscator'),
              true
            )
            assert.strictEqual(matchedValue(waf, testCase.payload), '<Redacted>')
            const configPaths = waf.configPaths

            const updateResult = waf.createOrUpdateConfig({
              obfuscator: {
                ...testCase.config,
                [testCase.field]: pattern
              }
            }, 'public/obfuscator')

            assert.strictEqual(matchedValue(waf, testCase.payload), '<Redacted>')
            assert.deepStrictEqual(waf.configPaths, configPaths)
            assert.strictEqual(updateResult, false)
          } finally {
            waf.dispose()
          }
        }
      }
    })

    it('should clear stale diagnostics when obfuscator validation rejects an update', () => {
      const rejected = [
        { key_regex: '[' },
        { value_regex: '[' },
        { key_regex: 42 },
        { value_regex: 42 },
        null
      ]
      const waf = new DDWAF(rules, 'recommended')
      try {
        for (const obfuscator of rejected) {
          assert.strictEqual(waf.createOrUpdateConfig(rules, 'recommended'), true)
          const previousDiagnostics = waf.diagnostics
          assert.ok(previousDiagnostics.rules.loaded.length > 0)

          assert.strictEqual(waf.createOrUpdateConfig({ obfuscator }, 'recommended'), false)
          assert.notStrictEqual(waf.diagnostics, previousDiagnostics)
          assert.deepStrictEqual(waf.diagnostics, {})
          assert.deepStrictEqual(waf.configPaths, ['recommended'])
          assert.strictEqual(matchedValue(waf, valuePayload), 'value_attack')
        }

        assert.strictEqual(waf.createOrUpdateConfig(rules, 'recommended'), true)
        assert.ok(waf.diagnostics.rules.loaded.length > 0)
      } finally {
        waf.dispose()
      }
    })

    it('should throw if clearing rejected-update diagnostics fails without changing active rules', () => {
      const waf = new DDWAF(rules, 'recommended')
      try {
        Object.defineProperty(waf, 'diagnostics', {
          value: waf.diagnostics,
          writable: false,
          enumerable: true,
          configurable: false
        })

        assert.throws(
          () => waf.createOrUpdateConfig({ obfuscator: { key_regex: '[' } }, 'recommended'),
          Error
        )
        assert.deepStrictEqual(waf.configPaths, ['recommended'])
        assert.strictEqual(matchedValue(waf, valuePayload), 'value_attack')
      } finally {
        waf.dispose()
      }
    })

    it('should reject malformed same-path obfuscator shapes without weakening active protection', () => {
      const malformed = [
        null,
        { key_regex: 42, value_regex: '' },
        { key_regex: 'password', value_regex: 42 },
        {
          toJSON () { throw new Error('nested obfuscator conversion failed') }
        }
      ]

      for (const obfuscator of malformed) {
        const waf = new DDWAF(rules, 'recommended')
        try {
          assert.strictEqual(
            waf.createOrUpdateConfig({
              obfuscator: { key_regex: 'password', value_regex: '' }
            }, 'public/obfuscator-shape'),
            true
          )
          assert.strictEqual(matchedValue(waf, keyPayload), '<Redacted>')
          const configPaths = waf.configPaths

          const updateResult = waf.createOrUpdateConfig({ obfuscator }, 'public/obfuscator-shape')

          assert.strictEqual(matchedValue(waf, keyPayload), '<Redacted>')
          assert.deepStrictEqual(waf.configPaths, configPaths)
          assert.strictEqual(updateResult, false)
        } finally {
          waf.dispose()
        }
      }
    })
  })
})
