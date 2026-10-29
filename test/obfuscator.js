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

  describe('obfuscator configuration', () => {
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

    it('should ignore inherited constructor obfuscator options', () => {
      const options = Object.create({
        obfuscatorKeyRegex: 'password',
        obfuscatorValueRegex: 'value_attack'
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
  })
})
