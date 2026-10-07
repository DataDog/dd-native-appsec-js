/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
const { it, describe } = require('mocha')
const assert = require('assert')
const { spawnSync } = require('child_process')
const { DDWAF } = require('..')
const rules = require('./rules.json')
const processor = require('./processor.json')

const TIMEOUT = 9999e3

function assertOwnDataProperty (object, property) {
  const descriptor = Object.getOwnPropertyDescriptor(object, property)
  assert(descriptor, `${property} must be an own property`)
  assert(Object.prototype.hasOwnProperty.call(descriptor, 'value'), `${property} must be a data property`)
  assert.strictEqual(descriptor.writable, true)
  assert.strictEqual(descriptor.enumerable, true)
  assert.strictEqual(descriptor.configurable, true)
  return descriptor.value
}

function withInheritedSetters (prototype, properties, callback) {
  const descriptors = new Map(properties.map(property => [
    property,
    Object.getOwnPropertyDescriptor(prototype, property)
  ]))
  const calls = new Map(properties.map(property => [property, 0]))

  try {
    for (const property of properties) {
      Object.defineProperty(prototype, property, {
        configurable: true,
        get () { return undefined },
        set () { calls.set(property, calls.get(property) + 1) }
      })
    }
    return callback(calls)
  } finally {
    for (const [property, descriptor] of descriptors) {
      if (descriptor) {
        Object.defineProperty(prototype, property, descriptor)
      } else {
        delete prototype[property]
      }
    }
  }
}

describe('addon export publication', () => {
  it('should define its own DDWAF export without invoking inherited setters', () => {
    const child = spawnSync(process.execPath, ['-e', `
      const assert = require('assert')
      const descriptor = Object.getOwnPropertyDescriptor(Object.prototype, 'DDWAF')
      let setterCalls = 0
      try {
        Object.defineProperty(Object.prototype, 'DDWAF', {
          configurable: true,
          get () { return undefined },
          set () { setterCalls++ }
        })
        const addon = require(${JSON.stringify(require.resolve('..'))})
        const own = Object.getOwnPropertyDescriptor(addon, 'DDWAF')
        assert.strictEqual(setterCalls, 0)
        assert(own)
        assert.strictEqual(typeof own.value, 'function')
        assert.strictEqual(typeof own.value.version, 'function')
      } finally {
        if (descriptor) {
          Object.defineProperty(Object.prototype, 'DDWAF', descriptor)
        } else {
          delete Object.prototype.DDWAF
        }
      }
    `], { encoding: 'utf8' })

    assert.strictEqual(child.signal, null, child.stderr)
    assert.strictEqual(child.status, 0, child.stderr)
  })
})

describe('DDWAF', () => {
  describe('prototype-safe native publication', () => {
    it('should decode __proto__ as an own data property without changing the object prototype', () => {
      const body = {}
      Object.defineProperty(body, '__proto__', {
        value: 'value',
        writable: true,
        enumerable: true,
        configurable: true
      })
      const waf = new DDWAF(processor, 'processor_rules')
      let context

      try {
        context = waf.createContext()
        const result = context.run({
          'server.request.body': body,
          'waf.context.processor': { 'extract-schema': true }
        }, TIMEOUT)
        const schema = result.attributes['server.request.body.schema'][0]

        assert.strictEqual(Object.getPrototypeOf(schema), Object.prototype)
        assert.deepStrictEqual(assertOwnDataProperty(schema, '__proto__'), [8])
      } finally {
        if (context) context.dispose()
        waf.dispose()
      }
    })

    it('should not invoke inherited setters for decoded map keys', () => {
      const property = 'decodedNativeProperty'
      const waf = new DDWAF(processor, 'processor_rules')
      let context

      try {
        context = waf.createContext()
        const { calls, result } = withInheritedSetters(Object.prototype, [property], setterCalls => ({
          calls: setterCalls,
          result: context.run({
            'server.request.body': { [property]: 'value' },
            'waf.context.processor': { 'extract-schema': true }
          }, TIMEOUT)
        }))
        const schema = result.attributes['server.request.body.schema'][0]

        assert.strictEqual(calls.get(property), 0)
        assert.deepStrictEqual(assertOwnDataProperty(schema, property), [8])
      } finally {
        if (context) context.dispose()
        waf.dispose()
      }
    })

    it('should publish WAF metadata as own data properties without invoking inherited setters', () => {
      const properties = ['diagnostics', 'knownAddresses', 'knownActions']
      let waf

      try {
        const calls = withInheritedSetters(DDWAF.prototype, properties, setterCalls => {
          waf = new DDWAF(rules, 'recommended')
          return setterCalls
        })

        for (const property of properties) {
          assert.strictEqual(calls.get(property), 0)
          assertOwnDataProperty(waf, property)
        }
      } finally {
        if (waf && !waf.disposed) waf.dispose()
      }
    })

    it('should publish evaluation fields as own data properties without invoking inherited setters', () => {
      const properties = ['metrics', 'status', 'events', 'actions', 'attributes']
      const waf = new DDWAF(rules, 'recommended')
      let context

      try {
        context = waf.createContext()
        const { calls, result } = withInheritedSetters(Object.prototype, properties, setterCalls => ({
          calls: setterCalls,
          result: context.run({
            'server.request.headers.no_cookies': 'marshalling'
          }, TIMEOUT)
        }))

        for (const property of properties) {
          assert.strictEqual(calls.get(property), 0)
          assertOwnDataProperty(result, property)
        }
      } finally {
        if (context) context.dispose()
        waf.dispose()
      }
    })

    it('should define own numeric array entries without invoking inherited setters', () => {
      const child = spawnSync(process.execPath, ['-e', `
        const assert = require('assert')
        const { DDWAF } = require(${JSON.stringify(require.resolve('..'))})
        const rules = require(${JSON.stringify(require.resolve('./rules.json'))})
        const descriptor = Object.getOwnPropertyDescriptor(Array.prototype, '0')
        const update = {
          rules_data: [{
            id: 'blocked_ips',
            type: 'ip_with_expiration',
            data: [{ value: '123.123.123.123' }]
          }]
        }
        let setterCalls = 0
        let waf
        let context
        let result
        let configPaths
        let diagnosticRules
        let knownAddresses
        let knownActions
        try {
          Object.defineProperty(Array.prototype, '0', {
            configurable: true,
            get () { return undefined },
            set () { setterCalls++ }
          })
          waf = new DDWAF(rules, 'recommended')
          context = waf.createContext()
          result = context.run({
            'server.request.headers.no_cookies': 'value_attack'
          }, ${TIMEOUT})
          configPaths = waf.configPaths
          diagnosticRules = waf.diagnostics.rules.loaded
          waf.createOrUpdateConfig(update, 'config/update')
          knownAddresses = waf.knownAddresses
          knownActions = waf.knownActions
        } finally {
          if (descriptor) {
            Object.defineProperty(Array.prototype, '0', descriptor)
          } else {
            delete Array.prototype[0]
          }
          if (context) context.dispose()
          if (waf && !waf.disposed) waf.dispose()
        }

        assert.strictEqual(setterCalls, 0)
        assert(Object.prototype.hasOwnProperty.call(result.events, '0'))
        assert.strictEqual(result.events[0].rule.id, 'value_attack')
        assert(Object.prototype.hasOwnProperty.call(configPaths, '0'))
        assert.strictEqual(configPaths[0], 'recommended')
        assert(Object.prototype.hasOwnProperty.call(diagnosticRules, '0'))
        assert.strictEqual(diagnosticRules[0], 'block_ip')
        assert(knownAddresses.has('http.client_ip'))
        assert(knownActions.has('block_request'))
      `], { encoding: 'utf8' })

      assert.strictEqual(child.signal, null, child.stderr)
      assert.strictEqual(child.status, 0, child.stderr)
    })

    it('should survive WAF disposal from a numeric setter during known metadata publication', () => {
      const child = spawnSync(process.execPath, ['-e', `
        const assert = require('assert')
        const { DDWAF } = require(${JSON.stringify(require.resolve('..'))})
        const rules = require(${JSON.stringify(require.resolve('./rules.json'))})
        const waf = new DDWAF(rules, 'recommended')
        const descriptor = Object.getOwnPropertyDescriptor(Array.prototype, '0')
        const ruleData = [{
          id: 'blocked_ips',
          type: 'ip_with_expiration',
          data: [{ value: '123.123.123.123' }]
        }]
        const update = {}
        Object.defineProperty(update, 'rules_data', {
          enumerable: true,
          get () {
            Object.defineProperty(Array.prototype, '0', {
              configurable: true,
              get () { return undefined },
              set (value) {
                Object.defineProperty(this, '0', {
                  value,
                  writable: true,
                  enumerable: true,
                  configurable: true
                })
                if (value === 'value_attack') waf.dispose()
              }
            })
            return ruleData
          }
        })

        let outcome
        try {
          try {
            outcome = waf.createOrUpdateConfig(update, 'config/update')
          } catch (error) {
            assert(error instanceof Error)
            outcome = 'error'
          }
        } finally {
          if (descriptor) {
            Object.defineProperty(Array.prototype, '0', descriptor)
          } else {
            delete Array.prototype[0]
          }
          if (!waf.disposed) waf.dispose()
        }

        assert(outcome === true || outcome === false || outcome === 'error')
      `], { encoding: 'utf8' })

      assert.strictEqual(child.signal, null, child.stderr)
      assert.strictEqual(child.status, 0, child.stderr)
    })

    it('should keep an accepted update active when frozen WAF metadata rejects publication', () => {
      const ipToBlock = '123.123.123.123'
      const waf = new DDWAF(rules, 'recommended')
      let context

      try {
        Object.freeze(waf)
        assert.throws(() => waf.createOrUpdateConfig({
          rules_data: [{
            id: 'blocked_ips',
            type: 'ip_with_expiration',
            data: [{ value: ipToBlock }]
          }]
        }, 'config/update'))

        context = waf.createContext()
        const result = context.run({ 'http.client_ip': ipToBlock }, TIMEOUT)
        assert.strictEqual(result.status, 'match')
      } finally {
        if (context) context.dispose()
        waf.dispose()
      }
    })
  })
})
