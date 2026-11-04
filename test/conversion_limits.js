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

function createNestedObject (n, obj) {
  if (n > 0) {
    return { a: createNestedObject(n - 1, obj) }
  }

  return obj
}
