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
  it('should ignore elements too far in the objects', () => {
    const waf = new DDWAF(rules, 'recommended')

    const context1 = waf.createContext()
    const result1 = context1.run({
      'server.response.status': {
        a0: '404'
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
      'server.response.status': item
    }, TIMEOUT)
    assert(!result2.status)
    assert(!result2.events)
    assert.strictEqual(result2.metrics.maxTruncatedContainerSize, length)
  })

  it('should match a moderately deeply nested object', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    const result = context.run({
      'server.request.headers.no_cookies': createNestedObject(5, { header: 'value_attack' })
    }, TIMEOUT)

    assert.strictEqual(result.status, 'match')
    assert.deepStrictEqual(result.metrics, {})
    assert(result.events)
  })

  it('should not match an extremely deeply nested object', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    const result = context.run({
      'server.request.headers.no_cookies': createNestedObject(100, { header: 'value_attack' })
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

  it('should truncate string values exceeding maximum length', () => {
    const waf = new DDWAF(rules, 'recommended')

    const context1 = waf.createContext()
    const result1 = context1.run({
      'server.response.status': '404'
    }, TIMEOUT)
    assert.strictEqual(result1.status, 'match')
    assert(result1.events)

    const longValue = 'a'.repeat(5000)

    const context2 = waf.createContext()
    const result2 = context2.run({
      'server.response.status': longValue,
      'server.request.body': { a: longValue + 'a' }
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
      'server.request.body': {
        deep1: deepObject1,
        large1: largeObject1,
        deep2: deepObject2,
        large2: largeObject2,
        str1: longValue1,
        str2: longValue2
      }
    }, TIMEOUT)

    assert(!result.status)
    assert(!result.events)
    assert.strictEqual(result.metrics.maxTruncatedString, 6000)
    assert.strictEqual(result.metrics.maxTruncatedContainerSize, 400)
    assert.strictEqual(result.metrics.maxTruncatedContainerDepth, 20)
  })
})

function createNestedObject (n, obj) {
  if (n > 0) {
    return { a: createNestedObject(n - 1, obj) }
  }

  return obj
}

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
