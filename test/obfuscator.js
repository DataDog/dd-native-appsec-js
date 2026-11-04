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
})
