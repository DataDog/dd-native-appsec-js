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
  it('should stop before later getters after exhausting the cumulative request node budget', () => {
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

      assert.strictEqual(getterCalls, 0)
      assert.strictEqual(result.status, undefined)
      assert.strictEqual(result.events, undefined)
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
      assert.strictEqual(result.metrics.truncatedByByteLimit, undefined)
    } finally {
      if (context) context.dispose()
      waf.dispose()
    }
  })

  it('should count UTF-8 map key bytes before invoking the value getter', () => {
    const waf = new DDWAF(rules, 'recommended')
    let context
    let getterCalls = 0
    const payload = {}
    Object.defineProperty(payload, 'é'.repeat(524289), {
      enumerable: true,
      get () {
        getterCalls++
        return 'value_attack'
      }
    })

    try {
      context = waf.createContext()
      const result = context.run(payload, TIMEOUT)

      assert.strictEqual(getterCalls, 0)
      assert.strictEqual(result.status, undefined)
    } finally {
      if (context) context.dispose()
      waf.dispose()
    }
  })

  // The node and byte budgets are cumulative over the whole request payload, so
  // running out of either one silently drops the rest of the data unless the
  // result says which budget was exhausted.
  describe('cumulative request budget telemetry', () => {
    const BYTE_BUDGET = 1048576

    it('should report node budget exhaustion without a byte or container size metric', () => {
      // 25 arrays of 256 items charge 6427 nodes against the 5120 node budget
      // while every container stays within the 256 entry container limit.
      const waf = new DDWAF(rules, 'recommended')
      let context

      try {
        context = waf.createContext()
        const result = context.run({
          padding: Array.from({ length: 25 }, () => Array.from({ length: 256 }, (_, index) => index))
        }, TIMEOUT)

        assert.strictEqual(result.metrics.truncatedByByteLimit, undefined)
        assert.strictEqual(result.metrics.maxTruncatedContainerSize, undefined)
        assert.strictEqual(result.metrics.truncatedByNodeLimit, true)
      } finally {
        if (context) context.dispose()
        waf.dispose()
      }
    })

    it('should report byte budget exhaustion on an oversized key without a string maximum', () => {
      const waf = new DDWAF(rules, 'recommended')
      let context

      try {
        context = waf.createContext()
        const result = context.run({ ['k'.repeat(2000000)]: 'value' }, TIMEOUT)

        // Keys are never clamped to the string maximum, so none is reported.
        assert.strictEqual(result.metrics.maxTruncatedString, undefined)
        assert.strictEqual(result.metrics.truncatedByByteLimit, true)
      } finally {
        if (context) context.dispose()
        waf.dispose()
      }
    })

    it('should charge retained prefixes instead of original string lengths', () => {
      const first = 'a'.repeat(700000)
      const second = 'b'.repeat(700000)
      const waf = new DDWAF(rules, 'recommended')

      try {
        // Both retained prefixes fit even though the source strings exceed the
        // cumulative budget. Their original lengths still feed telemetry.
        for (const body of [{ first, second }, { second, first }]) {
          const context = waf.createContext()
          try {
            const result = context.run({ 'server.request.body': body }, TIMEOUT)

            assert.strictEqual(result.metrics.maxTruncatedString, 700000)
            assert.strictEqual(result.metrics.truncatedByByteLimit, undefined)
          } finally {
            context.dispose()
          }
        }
      } finally {
        waf.dispose()
      }
    })

    it('should exhaust the byte budget one byte past the address key and its value', () => {
      const value = 'a'.repeat(4096)
      const waf = new DDWAF(rules, 'recommended')
      const metricsOf = (length) => {
        const context = waf.createContext()
        try {
          return context.run({ ['k'.repeat(length)]: value }, TIMEOUT).metrics
        } finally {
          context.dispose()
        }
      }

      try {
        // The address key is charged before its value, so both share the budget.
        const exact = metricsOf(BYTE_BUDGET - value.length)
        assert.strictEqual(exact.truncatedByByteLimit, undefined)
        assert.strictEqual(exact.maxTruncatedString, undefined)

        assert.strictEqual(metricsOf(BYTE_BUDGET - value.length + 1).truncatedByByteLimit, true)
      } finally {
        waf.dispose()
      }
    })

    it('should report the original length of a string larger than the byte budget', () => {
      const value = 'a'.repeat(2000000)
      const waf = new DDWAF(rules, 'recommended')
      let context

      try {
        context = waf.createContext()
        const result = context.run({ 'server.request.body': value }, TIMEOUT)

        assert.strictEqual(result.metrics.truncatedByNodeLimit, undefined)
        assert.strictEqual(result.metrics.maxTruncatedString, value.length)
        assert.strictEqual(result.metrics.truncatedByByteLimit, undefined)
      } finally {
        if (context) context.dispose()
        waf.dispose()
      }
    })

    it('should report the original length of a Buffer larger than the byte budget', () => {
      const buffer = Buffer.alloc(2000000, 0x61)
      const waf = new DDWAF(rules, 'recommended')
      let context

      try {
        context = waf.createContext()
        const result = context.run({ 'server.request.body': buffer }, TIMEOUT)

        assert.strictEqual(result.metrics.truncatedByNodeLimit, undefined)
        assert.strictEqual(result.metrics.maxTruncatedString, buffer.length)
        assert.strictEqual(result.metrics.truncatedByByteLimit, undefined)
      } finally {
        if (context) context.dispose()
        waf.dispose()
      }
    })

    it('should preserve bounded string and byte prefixes in contexts and subcontexts', () => {
      const waf = new DDWAF(rules, 'recommended')
      const parent = waf.createContext()
      const text = 'ordinary'.repeat(150000)
      const bytes = Buffer.from(text)
      const unicode = 'a'.repeat(4095) + 'é' + 'ordinary'.repeat(150000)

      try {
        for (const scoped of [false, true]) {
          for (const [value, expected] of [
            [text, text.slice(0, 4096)],
            [bytes, text.slice(0, 4096)],
            [unicode, 'a'.repeat(4095)]
          ]) {
            const context = scoped ? parent.createSubcontext() : waf.createContext()
            try {
              const result = context.run({ value_attack: value }, TIMEOUT)
              assert.strictEqual(result.errorCode, undefined)
              assert.strictEqual(result.events[0].rule_matches[0].parameters[0].value, expected)
              assert.strictEqual(result.metrics.truncatedByByteLimit, undefined)
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
})
