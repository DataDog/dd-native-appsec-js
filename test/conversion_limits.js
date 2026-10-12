/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
const { it, describe } = require('mocha')
const assert = require('assert')
const { DDWAF } = require('..')
const rules = require('./rules.json')

const TIMEOUT = 9999e3

describe('limit tests', () => {
  it('should evaluate later addresses after a large number of earlier nodes', () => {
    const waf = new DDWAF(rules, 'recommended')
    let context
    let getterCalls = 0
    const payload = {
      padding: Array.from(
        { length: 20 },
        () => Array.from({ length: 256 }, (_, index) => index)
      )
    }
    Object.defineProperty(payload, 'server.request.headers.no_cookies', {
      enumerable: true,
      get () {
        getterCalls++
        return 'value_attack'
      }
    })

    try {
      context = waf.createContext()
      const result = context.run(payload, TIMEOUT)

      assert.strictEqual(getterCalls, 1)
      assert.strictEqual(result.status, 'match')
      assert.deepStrictEqual(result.metrics, {})
    } finally {
      if (context) context.dispose()
      waf.dispose()
    }
  })

  it('should retain later addresses after truncating a large UTF-8 value', () => {
    const waf = new DDWAF(rules, 'recommended')
    let context
    let getterCalls = 0
    const payload = {
      padding: 'é'.repeat(524289)
    }
    Object.defineProperty(payload, 'server.request.headers.no_cookies', {
      enumerable: true,
      get () {
        getterCalls++
        return 'value_attack'
      }
    })

    try {
      context = waf.createContext()
      const result = context.run(payload, TIMEOUT)

      assert.strictEqual(getterCalls, 1)
      assert.strictEqual(result.status, 'match')
      assert.strictEqual(result.metrics.maxTruncatedString, 1048578)
    } finally {
      if (context) context.dispose()
      waf.dispose()
    }
  })

  it('should evaluate later addresses after a large amount of earlier string data', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()
    try {
      const result = context.run({
        padding: new Array(256).fill('a'.repeat(4096)),
        'server.request.headers.no_cookies': 'value_attack'
      }, TIMEOUT)

      assert.strictEqual(result.status, 'match')
      assert.deepStrictEqual(result.metrics, {})
    } finally {
      context.dispose()
      waf.dispose()
    }
  })

  it('should report the original length of a large truncated string', () => {
    const value = 'a'.repeat(2000000)
    const waf = new DDWAF(rules, 'recommended')
    let context

    try {
      context = waf.createContext()
      const result = context.run({ 'server.request.body': value }, TIMEOUT)

      assert.strictEqual(result.metrics.maxTruncatedString, value.length)
    } finally {
      if (context) context.dispose()
      waf.dispose()
    }
  })

  it('should preserve bounded UTF-8 string prefixes in contexts and subcontexts', () => {
    const waf = new DDWAF(rules, 'recommended')
    const parent = waf.createContext()
    const text = 'ordinary'.repeat(150000)
    const unicode = 'a'.repeat(4095) + 'é' + 'ordinary'.repeat(150000)

    try {
      for (const scoped of [false, true]) {
        for (const [value, expected] of [
          [text, text.slice(0, 4096)],
          [unicode, 'a'.repeat(4095)]
        ]) {
          const context = scoped ? parent.createSubcontext() : waf.createContext()
          try {
            const result = context.run({ value_attack: value }, TIMEOUT)
            assert.strictEqual(result.errorCode, undefined)
            assert.strictEqual(result.events[0].rule_matches[0].parameters[0].value, expected)
            assert.strictEqual(result.metrics.maxTruncatedString, Buffer.byteLength(value))
          } finally {
            context.dispose()
          }
        }
      }
    } finally {
      parent.dispose()
      waf.dispose()
    }
  })
})
