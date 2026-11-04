/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
const { it, describe } = require('mocha')
const assert = require('assert')

const { DDWAF } = require('..')
const pkg = require('../package.json')
const rules = require('./rules.json')
const processor = require('./processor.json')

const TIMEOUT = 9999e3

describe('package manifest', () => {
  it('declares no npm build lifecycle scripts (Yarn Berry YN0007)', () => {
    const scripts = pkg.scripts || {}
    const hooks = ['preinstall', 'install', 'postinstall']
    const present = hooks.filter((name) => scripts[name] !== undefined)
    assert.deepStrictEqual(
      present,
      [],
      'package.json must not declare npm build lifecycle scripts (they trigger Yarn Berry YN0007)'
    )
  })

  it('opts out of npm implicit node-gyp rebuilds', () => {
    assert.strictEqual(pkg.gypfile, false)
  })
})

describe('DDWAF', () => {
  it('should return the version', () => {
    const v = DDWAF.version()

    assert.strictEqual(v, pkg.libddwaf_version)
  })

  it('should have diagnostics', () => {
    const waf = new DDWAF(rules, 'recommended')

    assert.deepStrictEqual(waf.diagnostics, {
      ruleset_version: '1.3.1',
      actions: {
        errors: {},
        warnings: {},
        failed: [],
        loaded: [
          'customblock'
        ],
        skipped: []
      },
      rules: {
        loaded: [
          'block_ip',
          'value_attack',
          'key_attack',
          'nfd-000-001',
          'value_matchall',
          'key_matchall',
          'custom_action_rule',
          'test-marshalling',
          'long_rule'
        ],
        skipped: [],
        failed: ['invalid_1', 'invalid_2', 'invalid_3'],
        errors: {
          'missing key \'regex\'': [
            'invalid_1'
          ],
          'invalid regular expression: *': [
            'invalid_2',
            'invalid_3'
          ]
        },
        warnings: {}
      }
    })
  })

  it('should have knownAddresses', () => {
    const waf = new DDWAF(rules, 'recommended')

    assert.deepStrictEqual(waf.knownAddresses, new Set([
      'http.client_ip',
      'server.request.headers.no_cookies',
      'server.response.status',
      'value_attack',
      'key_attack',
      'server.request.body',
      'custom_value_attack'
    ]))
  })

  it('should have knownActions', () => {
    const waf = new DDWAF(rules, 'recommended')

    assert.deepStrictEqual(waf.knownActions, new Set([
      'block_request'
    ]))
  })

  it('should collect an attack and cleanup everything', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()
    const payload = {
      persistent: {
        'server.request.headers.no_cookies': 'value_ATTack',
        x: new Array(4096).fill('x').join(''),
        y: new Array(4097).fill('y').join(''),
        z: new Array(4097).fill('z')
      }
    }

    const result = context.run(payload, TIMEOUT)

    assert.strictEqual(result.timeout, false)
    assert.strictEqual(result.status, 'match')
    assert(result.events)
    assert.deepStrictEqual(result.actions, {})
    assert(!context.disposed)

    context.dispose()
    assert(context.disposed)

    assert.throws(() => {
      context.run(payload, TIMEOUT)
    }, new Error('Calling run on a disposed context'))
    assert(!waf.disposed)

    waf.dispose()
    assert(waf.disposed)

    assert.throws(() => {
      waf.createContext()
    }, new Error('Calling createContext on a disposed DDWAF instance'))
  })

  it('should collect different attacks on ephemeral addresses', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()
    let result = context.run({
      ephemeral: {
        'server.request.headers.no_cookies': 'value_ATTack'
      }
    }, TIMEOUT)

    assert.strictEqual(result.timeout, false)
    assert.strictEqual(result.status, 'match')
    assert.strictEqual(result.events[0].rule_matches[0].parameters[0].value, 'value_attack')
    assert.deepStrictEqual(result.actions, {})
    assert.deepStrictEqual(result.metrics, {})

    result = context.run({
      ephemeral: {
        'server.request.headers.no_cookies': 'other_attack'
      }
    }, TIMEOUT)

    assert.strictEqual(result.timeout, false)
    assert.strictEqual(result.status, 'match')
    assert.strictEqual(result.events[0].rule_matches[0].parameters[0].value, 'other_attack')
    assert.deepStrictEqual(result.actions, {})
    assert.deepStrictEqual(result.metrics, {})

    context.dispose()

    waf.dispose()
  })

  it('should support case_sensitive', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    const result = context.run({
      persistent: {
        'server.response.status': '404'
      }
    }, TIMEOUT)

    assert.strictEqual(result.status, 'match')
    assert(result.events)
  })

  it('should refuse invalid rule', () => {
    assert.throws(() => new DDWAF({}, 'empty_rules'), new Error('Invalid rules'))
    assert.throws(() => new DDWAF('', 'non_object_rules'), new TypeError('First argument must be an object'))
  })

  it('should refuse to run with bad signatures', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    const wronArgsError = new Error('Wrong number of arguments, 2 expected')
    assert.throws(() => context.run(), wronArgsError)

    const payloadError = new TypeError('Payload data must be an object')
    assert.throws(() => context.run(null, TIMEOUT), payloadError)

    const objectError = new TypeError('Persistent or ephemeral must be an object')
    assert.throws(() => context.run({}, TIMEOUT), objectError)
    assert.throws(() => context.run({ persistent: '' }, TIMEOUT), objectError)
    assert.throws(() => context.run({ persistent: '', ephemeral: null }, TIMEOUT), objectError)
    assert.throws(() => context.run({ ephemeral: null }, TIMEOUT), objectError)

    const numberError = new TypeError('Timeout argument must be a number')
    assert.throws(() => context.run({ persistent: {}, ephemeral: {} }, ''), numberError)

    const greaterError = new TypeError('Timeout argument must be greater than 0')
    assert.throws(() => context.run({
      persistent: {
        'server.request.headers.no_cookies': 'value_attack'
      }
    }, -1), greaterError)
    assert.throws(() => context.run({
      persistent: {
        'server.request.headers.no_cookies': 'value_attack'
      }
    }, 0), greaterError)
  })

  it('should collect result attributes information when a rule match', () => {
    const waf = new DDWAF(processor, 'processor_rules')

    const context = waf.createContext()

    assert(waf.diagnostics.processors.loaded.includes('processor-001'))
    assert.equal(waf.diagnostics.processors.failed.length, 0)

    const result = context.run({
      persistent: {
        'server.request.body': 'value',
        'waf.context.processor': {
          'extract-schema': true
        }
      }
    }, TIMEOUT)

    assert.strictEqual(result.status, 'match')
    assert.deepStrictEqual(result.attributes, { 'server.request.body.schema': [8] })

    context.dispose()
    assert(context.disposed)

    waf.dispose()
    assert(waf.disposed)
  })

  it('should collect result attributes information when a rule does not match', () => {
    const waf = new DDWAF(processor, 'processor_rules')
    const context = waf.createContext()

    assert(waf.diagnostics.processors.loaded.includes('processor-001'))
    assert.equal(waf.diagnostics.processors.failed.length, 0)

    const result = context.run({
      persistent: {
        'server.request.body': '',
        'waf.context.processor': {
          'extract-schema': true
        }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.attributes, { 'server.request.body.schema': [8] })

    context.dispose()
    assert(context.disposed)

    waf.dispose()
    assert(waf.disposed)
  })

  it('should collect all result attributes types', () => {
    const waf = new DDWAF(processor, 'processor_rules')
    const context = waf.createContext()

    assert(waf.diagnostics.processors.loaded.includes('processor-001'))
    assert.equal(waf.diagnostics.processors.failed.length, 0)

    const result = context.run({
      persistent: {
        'server.request.body': {
          null: null,
          integer: 42,
          float: 42.42,
          infinity: Infinity,
          nan: NaN,
          signed: -42,
          boolean: true,
          string: 'string',
          array: [1, 2, 3],
          obj: { key: 'value' },
          undefined: undefined,
          bigint: BigInt(42),
          regex: /regex/,
          function: function fn () {}
        },
        'waf.context.processor': {
          'extract-schema': true
        }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.attributes, {
      'server.request.body.schema': [
        {
          null: [1],
          boolean: [2],
          float: [16],
          infinity: [16],
          nan: [16],
          integer: [16],
          signed: [16],
          string: [8],
          array: [[[16]], { len: 3 }],
          obj: [{ key: [8] }],
          undefined: [0],
          bigint: [0],
          regex: [{}],
          function: [0]
        }
      ]
    })

    context.dispose()
    assert(context.disposed)

    waf.dispose()
    assert(waf.disposed)
  })

  it('should collect result attributes in two consecutive calls', () => {
    const waf = new DDWAF(processor, 'processor_rules')
    const context = waf.createContext()

    assert(waf.diagnostics.processors.loaded.includes('processor-001'))
    assert.equal(waf.diagnostics.processors.failed.length, 0)

    let result = context.run({
      persistent: {
        'server.request.body': ''
      }
    }, TIMEOUT)

    assert.strictEqual(result.attributes, undefined)

    result = context.run({
      persistent: {
        'server.request.body': '',
        'waf.context.processor': {
          'extract-schema': true
        }
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.attributes, { 'server.request.body.schema': [8] })

    result = context.run({
      persistent: {
        'server.request.query': ''
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.attributes, { 'server.request.query.schema': [8] })

    context.dispose()
    assert(context.disposed)

    waf.dispose()
    assert(waf.disposed)
  })

  it('should include keep field in result object', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    // Non-match result
    let result = context.run({
      persistent: {
        'server.request.headers.no_cookies': 'normal_value'
      }
    }, TIMEOUT)

    assert.strictEqual(result.timeout, false)
    assert.strictEqual(typeof result.keep, 'boolean')
    assert.strictEqual(result.keep, false)

    // Match result
    result = context.run({
      persistent: {
        'server.request.headers.no_cookies': 'value_attack'
      }
    }, TIMEOUT)

    assert.strictEqual(result.timeout, false)
    assert.strictEqual(result.status, 'match')
    assert.strictEqual(typeof result.keep, 'boolean')
    assert.strictEqual(result.keep, true)

    context.dispose()
    waf.dispose()
  })

  describe('Action semantics', () => {
    it('should support action definition in initialisation', () => {
      const waf = new DDWAF(rules, 'recommended')
      const context = waf.createContext()

      const result = context.run({
        persistent: {
          custom_value_attack: 'match'
        }
      }, TIMEOUT)

      assert.strictEqual(result.timeout, false)
      assert.strictEqual(result.status, 'match')
      assert(result.events)
      assert.deepStrictEqual(result.actions, {
        block_request: {
          security_response_id: result?.actions?.block_request?.security_response_id,
          grpc_status_code: 10,
          status_code: 418,
          type: 'auto'
        }
      })
      assert.deepStrictEqual(result.metrics, {})
    })

    it('should support action definition in update', () => {
      const waf = new DDWAF(rules, 'recommended')

      const updatedRules = Object.assign({}, rules)
      updatedRules.actions = [{
        id: 'customblock',
        type: 'block_request',
        parameters: {
          status_code: '404',
          grpc_status_code: '10',
          type: 'auto'
        }
      }]

      waf.removeConfig('recommended')
      waf.createOrUpdateConfig(updatedRules, 'recommended_action_modified')

      const context = waf.createContext()
      const resultWithUpdatedAction = context.run({
        persistent: {
          custom_value_attack: 'match'
        }
      }, TIMEOUT)

      assert.strictEqual(resultWithUpdatedAction.timeout, false)
      assert.strictEqual(resultWithUpdatedAction.status, 'match')
      assert(resultWithUpdatedAction.events)
      assert.deepStrictEqual(resultWithUpdatedAction.actions, {
        block_request: {
          security_response_id: resultWithUpdatedAction?.actions?.block_request?.security_response_id,
          grpc_status_code: 10,
          status_code: 404,
          type: 'auto'
        }
      })
      assert.deepStrictEqual(resultWithUpdatedAction.metrics, {})
    })
  })
})

describe('Handle errors', () => {
  it('should handle invalid arguments number', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    try {
      context.run({
        persistent: {}
      })
    } catch (e) {
      assert.strictEqual(e.message, 'Wrong number of arguments, 2 expected')
    }
  })

  it('should handle invalid timeout arguments', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    try {
      context.run({
        persistent: {}
      }, 'TIMEOUT')
    } catch (e) {
      assert.strictEqual(e.message, 'Timeout argument must be a number')
    }

    try {
      context.run({
        persistent: {}
      }, 0)
    } catch (e) {
      assert.strictEqual(e.message, 'Timeout argument must be greater than 0')
    }
  })

  it('should handle invalid arguments', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    try {
      context.run({
        persistent: 'invalid_object'
      }, TIMEOUT)
    } catch (e) {
      assert.strictEqual(e.message, 'Persistent or ephemeral must be an object')
    }
  })
})
