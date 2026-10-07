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
const matchedValue = require('./helpers/matched_value')

const TIMEOUT = 9999e3

describe('DDWAF', () => {
  // A normalisation step used to map every infinity to +Infinity, so a rule
  // bounded below would stop matching -Infinity.
  it('should preserve the sign of -Infinity', () => {
    const signedRules = {
      version: '2.2',
      metadata: { rules_version: '1.0.0' },
      rules: [{
        id: 'below-zero',
        name: 'below zero',
        tags: { type: 'test', category: 'test' },
        conditions: [{
          operator: 'lower_than',
          parameters: { inputs: [{ address: 'server.request.query' }], type: 'float', value: 0 }
        }],
        transformers: []
      }]
    }

    const waf = new DDWAF(signedRules, 'signed')
    const matches = (value) => {
      const context = waf.createContext()
      const status = context.run({ 'server.request.query': value }, TIMEOUT).status
      context.dispose()
      return status === 'match'
    }

    assert.strictEqual(matches(-Infinity), true)
    assert.strictEqual(matches(Infinity), false)
    assert.strictEqual(matches(-1.5), true)
    assert.strictEqual(matches(1.5), false)

    waf.dispose()
  })
})

describe('limit tests', () => {
  it('should detect an ancestor cycle at the deepest traversed request level', () => {
    const payload = {}
    let cursor = payload
    // Sixteen children leave the cycle marker observable before the depth-20 cutoff.
    for (let depth = 0; depth < 16; depth++) {
      cursor.child = {}
      cursor = cursor.child
    }
    cursor.cycle = payload

    const waf = new DDWAF(processor, 'processor_rules')
    let context
    try {
      context = waf.createContext()
      const result = context.run({
        'server.request.body': payload,
        'waf.context.processor': { 'extract-schema': true }
      }, TIMEOUT)

      let schema = result.attributes['server.request.body.schema'][0]
      for (let depth = 0; depth < 16; depth++) {
        assert.strictEqual(schema.child.length, 1)
        schema = schema.child[0]
      }
      assert.deepStrictEqual(schema.cycle, [0])
    } finally {
      if (context) context.dispose()
      waf.dispose()
    }
  })

  it('should fully decode aliases reused beneath separate sibling branches', () => {
    const shared = {
      value: 'shared',
      nested: { value: 'nested' }
    }
    const payload = {
      left: { shared },
      right: { shared }
    }
    const waf = new DDWAF(processor, 'processor_rules')
    let context

    try {
      context = waf.createContext()
      const result = context.run({
        'server.request.body': payload,
        'waf.context.processor': { 'extract-schema': true }
      }, TIMEOUT)
      const schema = result.attributes['server.request.body.schema'][0]

      for (const branch of ['left', 'right']) {
        const decoded = schema[branch][0].shared[0]
        assert.deepStrictEqual(decoded.value, [8])
        assert.deepStrictEqual(decoded.nested[0].value, [8])
      }
    } finally {
      if (context) context.dispose()
      waf.dispose()
    }
  })
})

describe('ddwaf_object marshalling', () => {
  // libddwaf 2.x strings are length delimited rather than NUL terminated, so an
  // embedded NUL must survive the round trip instead of truncating the string.
  it('should preserve strings containing NUL bytes', () => {
    const waf = new DDWAF(rules, 'recommended')

    for (const key of ['a\u0000b', '\u0000leading', 'trailing\u0000', 'a\u0000\u0000b']) {
      const context = waf.createContext()
      const result = context.run({ key_attack: { [key]: 'value' } }, TIMEOUT)

      assert.strictEqual(result.status, 'match')
      assert.strictEqual(result.events[0].rule_matches[0].parameters[0].value, key)
      context.dispose()
    }

    waf.dispose()
  })

  // Strings of up to 14 bytes are stored inline in the ddwaf_object in 2.x,
  // which is a different union member than heap allocated strings. An empty key
  // is not covered here because key_attack does not match one.
  it('should round trip strings across the small string boundary', () => {
    const waf = new DDWAF(rules, 'recommended')

    for (const length of [1, 13, 14, 15, 16, 100]) {
      const key = 'k'.repeat(length)
      const context = waf.createContext()
      const result = context.run({ key_attack: { [key]: 'value' } }, TIMEOUT)

      assert.strictEqual(result.status, 'match')
      assert.strictEqual(result.events[0].rule_matches[0].parameters[0].value, key)
      context.dispose()
    }

    waf.dispose()
  })

  it('should convert Buffer bytes without invoking instance or prototype toJSON', () => {
    const waf = new DDWAF(rules, 'recommended')
    const runBuffer = (buffer) => {
      const context = waf.createContext()
      try {
        return context.run({
          'server.request.headers.no_cookies': buffer
        }, TIMEOUT)
      } finally {
        context.dispose()
      }
    }

    try {
      const instanceBuffer = Buffer.from('value_attack')
      const instanceToJSON = Object.getOwnPropertyDescriptor(instanceBuffer, 'toJSON')
      let instanceCalls = 0
      let instanceResult
      try {
        Object.defineProperty(instanceBuffer, 'toJSON', {
          configurable: true,
          value () {
            instanceCalls++
            throw new Error('Buffer instance toJSON must not be called')
          }
        })
        instanceResult = runBuffer(instanceBuffer)
      } finally {
        if (instanceToJSON) {
          Object.defineProperty(instanceBuffer, 'toJSON', instanceToJSON)
        } else {
          delete instanceBuffer.toJSON
        }
      }

      assert.strictEqual(instanceCalls, 0)
      assert.strictEqual(instanceResult.status, 'match')
      assert.strictEqual(instanceResult.events[0].rule_matches[0].parameters[0].value, 'value_attack')

      const prototypeToJSON = Object.getOwnPropertyDescriptor(Buffer.prototype, 'toJSON')
      let prototypeCalls = 0
      let prototypeResult
      try {
        Object.defineProperty(Buffer.prototype, 'toJSON', {
          configurable: true,
          value () {
            prototypeCalls++
            throw new Error('Buffer prototype toJSON must not be called')
          }
        })
        prototypeResult = runBuffer(Buffer.from('value_attack'))
      } finally {
        Object.defineProperty(Buffer.prototype, 'toJSON', prototypeToJSON)
      }

      assert.strictEqual(prototypeCalls, 0)
      assert.strictEqual(prototypeResult.status, 'match')
      assert.strictEqual(prototypeResult.events[0].rule_matches[0].parameters[0].value, 'value_attack')
    } finally {
      waf.dispose()
    }
  })

  it('should only convert byte views as raw bytes', () => {
    const waf = new DDWAF(rules, 'recommended')
    const runView = (view) => {
      const context = waf.createContext()
      try {
        return context.run({
          'server.request.headers.no_cookies': view
        }, TIMEOUT)
      } finally {
        context.dispose()
      }
    }

    try {
      for (const view of [
        Buffer.from('value_attack'),
        new Uint8Array(Buffer.from('value_attack')),
        new Uint8ClampedArray(Buffer.from('value_attack'))
      ]) {
        const result = runView(view)
        assert.strictEqual(result.status, 'match')
        assert.strictEqual(result.events[0].rule_matches[0].parameters[0].value, 'value_attack')
      }

      const bytes = new Uint8Array(Buffer.from('value_attack'))
      let toJSONCalls = 0
      bytes.toJSON = () => {
        toJSONCalls++
        throw new Error('Uint8Array toJSON must not be called')
      }
      const bytesResult = runView(bytes)
      assert.strictEqual(toJSONCalls, 0)
      assert.strictEqual(bytesResult.status, 'match')
      assert.strictEqual(bytesResult.events[0].rule_matches[0].parameters[0].value, 'value_attack')

      const dataView = new DataView(new Uint8Array(Buffer.from('value_attack')).buffer)
      let dataViewResult
      assert.doesNotThrow(() => {
        dataViewResult = runView(dataView)
      })
      assert.strictEqual(dataViewResult.status, undefined)

      const int32View = new Int32Array(new Uint8Array(Buffer.from('value_attack')).buffer)
      assert.strictEqual(runView(int32View).status, undefined)

      const float64View = new Float64Array(new Uint8Array(Buffer.from('value_attackxxxx')).buffer)
      assert.strictEqual(runView(float64View).status, undefined)
    } finally {
      waf.dispose()
    }
  })

  it('should report long Buffer byte length as string truncation', () => {
    const buffer = Buffer.alloc(4097, 0x61)
    const waf = new DDWAF(rules, 'recommended')
    let context

    try {
      context = waf.createContext()
      const result = context.run({ 'server.request.body': buffer }, TIMEOUT)

      assert.strictEqual(result.metrics.maxTruncatedString, buffer.length)
      assert.strictEqual(result.metrics.maxTruncatedContainerSize, undefined)
    } finally {
      if (context) context.dispose()
      waf.dispose()
    }
  })

  // A throwing getter used to reach an N-API call with an exception already
  // pending, which is fatal under NAPI_DISABLE_CPP_EXCEPTIONS.
  it('should propagate a throwing getter instead of aborting', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    const data = {}
    Object.defineProperty(data, 'server.request.headers.no_cookies', {
      enumerable: true,
      get () { throw new Error('boom from getter') }
    })

    assert.throws(() => context.run(data, TIMEOUT), /boom from getter/)

    context.dispose()
    waf.dispose()
  })

  // Cycle detection and the known-address sets both used JS Set operations,
  // which an application can replace. A throw from one of those must surface as
  // a JS error rather than a fatal N-API call.
  // knownAddresses/knownActions are built with the global Set, which an
  // application can replace. Each of these used to abort the process.
  it('should survive a hostile global Set', () => {
    const NativeSet = globalThis.Set
    const withGlobalSet = (replacement, assertion) => {
      globalThis.Set = replacement
      try {
        assertion()
      } finally {
        globalThis.Set = NativeSet
      }
    }

    // `new Set(iterable)` calls add() per element, so a throwing add must
    // surface as a JS error rather than a fatal N-API call.
    withGlobalSet(class extends NativeSet {
      add () { throw new Error('boom add') }
    }, () => {
      assert.throws(() => new DDWAF(rules, 'recommended'), /boom add/)
    })

    withGlobalSet(function NotAConstructor () {}, () => {
      assert.throws(() => new DDWAF(rules, 'recommended'), /Set did not produce a usable set/)
    })

    // Constructs fine but is not a Set, so knownAddresses would have no has().
    withGlobalSet(class {}, () => {
      assert.throws(() => new DDWAF(rules, 'recommended'), /Set did not produce a usable set/)
    })

    withGlobalSet(42, () => {
      assert.throws(() => new DDWAF(rules, 'recommended'), /Set is not a constructor/)
    })

    // The native Set is restored, so the binding is usable again.
    const waf = new DDWAF(rules, 'recommended')
    assert.strictEqual(typeof waf.knownAddresses.has, 'function')
    assert(waf.knownAddresses.has('server.request.headers.no_cookies'))
    waf.dispose()
  })

  it('should propagate a throwing getter while building rules or a config', () => {
    const throwingRules = {}
    Object.defineProperty(throwingRules, 'rules', {
      enumerable: true,
      get () { throw new Error('boom rules') }
    })

    assert.throws(() => new DDWAF(throwingRules, 'recommended'), /boom rules/)

    const throwingOptions = {}
    Object.defineProperty(throwingOptions, 'obfuscatorKeyRegex', {
      enumerable: true,
      get () { throw new Error('boom option') }
    })
    assert.throws(() => new DDWAF(rules, 'recommended', throwingOptions), /boom option/)

    const waf = new DDWAF(rules, 'recommended')
    assert.throws(() => waf.createOrUpdateConfig(throwingRules, 'config/update'), /boom rules/)
    assert.throws(
      () => waf.createOrUpdateConfig(new Proxy({}, { ownKeys () { throw new Error('boom ownKeys') } }), 'config/u2'),
      /boom ownKeys/
    )

    assert.strictEqual(
      waf.createContext().run({ 'server.request.headers.no_cookies': 'value_ATTack' }, TIMEOUT).status,
      'match'
    )
    waf.dispose()
  })

  it('should throw instead of calling libddwaf after a config getter disposes the WAF', () => {
    const child = spawnSync(process.execPath, ['-e', `
      const { DDWAF } = require(${JSON.stringify(require.resolve('..'))})
      const rules = require(${JSON.stringify(require.resolve('./rules.json'))})
      const waf = new DDWAF(rules, 'recommended')
      const config = {}
      Object.defineProperty(config, 'rules', {
        enumerable: true,
        get () {
          waf.dispose()
          return []
        }
      })

      let failure
      try {
        waf.createOrUpdateConfig(config, 'config/update')
      } catch (error) {
        failure = error
      } finally {
        if (!waf.disposed) waf.dispose()
      }

      if (!(failure instanceof Error)) {
        throw new Error('Expected disposal during config marshalling to throw')
      }
      process.stdout.write('javascript-error:' + failure.message)
    `], { encoding: 'utf8' })

    assert.strictEqual(child.signal, null, child.stderr)
    assert.strictEqual(child.status, 0, child.stderr)
    assert.match(child.stdout, /^javascript-error:/)
  })

  it('should propagate a throwing proxy trap instead of aborting', () => {
    const waf = new DDWAF(rules, 'recommended')

    const ownKeysTrap = new Proxy({}, { ownKeys () { throw new Error('boom from ownKeys') } })
    const context1 = waf.createContext()
    assert.throws(() => context1.run(ownKeysTrap, TIMEOUT), /boom from ownKeys/)
    context1.dispose()

    const { proxy, revoke } = Proxy.revocable({ a: 1 }, {})
    revoke()
    const context2 = waf.createContext()
    assert.throws(() => context2.run(proxy, TIMEOUT), /revoked/)
    context2.dispose()

    waf.dispose()
  })

  // Marshalling re-enters JS, so the native handle latched before it can be
  // destroyed underneath the evaluation.
  it('should not evaluate when a getter disposes the context mid-marshalling', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    const data = {}
    Object.defineProperty(data, 'server.request.headers.no_cookies', {
      enumerable: true,
      get () { context.dispose(); return 'value_ATTack' }
    })

    assert.throws(
      () => context.run(data, TIMEOUT),
      new Error('Context was disposed while reading the data')
    )
    assert(context.disposed)

    waf.dispose()
  })

  it('should not evaluate when toJSON disposes the context mid-marshalling', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    const data = {
      'server.request.headers.no_cookies': {
        toJSON () { context.dispose(); return 'value_ATTack' }
      }
    }

    assert.throws(
      () => context.run(data, TIMEOUT),
      new Error('Context was disposed while reading the data')
    )

    waf.dispose()
  })

  it('should not evaluate when a getter disposes the subcontext mid-marshalling', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()
    const subcontext = context.createSubcontext()

    const data = {}
    Object.defineProperty(data, 'server.request.headers.no_cookies', {
      enumerable: true,
      get () { subcontext.dispose(); return 'value_ATTack' }
    })

    assert.throws(
      () => subcontext.run(data, TIMEOUT),
      new Error('Subcontext was disposed while reading the data')
    )

    context.dispose()
    waf.dispose()
  })

  it('should load rule data larger than a compact container', () => {
    const IP_TO_BLOCK = '123.123.123.123'
    const data = []
    for (let i = 0; i < 70000; i++) {
      data.push({ value: `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}` })
    }
    data.push({ value: IP_TO_BLOCK })

    const waf = new DDWAF(rules, 'recommended')
    const updated = waf.createOrUpdateConfig({
      rules_data: [
        { id: 'blocked_ips', type: 'ip_with_expiration', data }
      ]
    }, 'config/large')

    assert.strictEqual(updated, true)

    const context = waf.createContext()
    const result = context.run({ 'http.client_ip': IP_TO_BLOCK }, TIMEOUT)

    assert.strictEqual(result.status, 'match')
    assert(result.events)

    context.dispose()
    waf.dispose()
  })

  it('should load configuration maps across the compact container boundary', () => {
    const metadata = Object.fromEntries(Array.from({ length: 65535 }, (_, i) => [`key${i}`, i]))
    const waf = new DDWAF({ ...rules, metadata }, 'recommended')
    try {
      metadata.rules_version = 'large-map'
      assert.strictEqual(waf.createOrUpdateConfig({ ...rules, metadata }, 'recommended'), true)
      assert.strictEqual(waf.diagnostics.ruleset_version, 'large-map')
      assert.strictEqual(matchedValue(waf, { value_attack: 'ordinary' }), 'ordinary')
    } finally {
      waf.dispose()
    }
  })
})
