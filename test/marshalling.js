/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
const { it, describe } = require('mocha')
const assert = require('assert')

const { DDWAF } = require('..')
const rules = require('./rules.json')
const processor = require('./processor.json')

const TIMEOUT = 9999e3

describe('DDWAF', () => {
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
})

describe('limit tests', () => {
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
})
