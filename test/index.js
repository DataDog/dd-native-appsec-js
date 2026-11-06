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

function assertAbsent (object, property) {
  assert.strictEqual(
    Object.prototype.hasOwnProperty.call(object, property),
    false,
    `${property} must not be published`
  )
}

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
      'server.request.headers.no_cookies': 'value_ATTack',
      x: new Array(4096).fill('x').join(''),
      y: new Array(4097).fill('y').join(''),
      z: new Array(4097).fill('z')
    }

    const result = context.run(payload, TIMEOUT)

    assert.strictEqual(result.timeout, false)
    assert.strictEqual(result.status, 'match')
    assert(result.events)
    assertAbsent(result, 'actions')
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

  it('should collect different attacks on subcontexts', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    const subcontext1 = context.createSubcontext()
    let result = subcontext1.run({
      'server.request.headers.no_cookies': 'value_ATTack'
    }, TIMEOUT)

    assert.strictEqual(result.timeout, false)
    assert.strictEqual(result.status, 'match')
    assert.strictEqual(result.events[0].rule_matches[0].parameters[0].value, 'value_attack')
    assertAbsent(result, 'actions')
    assert.deepStrictEqual(result.metrics, {})
    subcontext1.dispose()
    assert(subcontext1.disposed)

    const subcontext2 = context.createSubcontext()
    result = subcontext2.run({
      'server.request.headers.no_cookies': 'other_attack'
    }, TIMEOUT)

    assert.strictEqual(result.timeout, false)
    assert.strictEqual(result.status, 'match')
    assert.strictEqual(result.events[0].rule_matches[0].parameters[0].value, 'other_attack')
    assertAbsent(result, 'actions')
    assert.deepStrictEqual(result.metrics, {})
    subcontext2.dispose()

    context.dispose()

    waf.dispose()
  })

  it('should support case_sensitive', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    const result = context.run({
      'server.response.status': '404'
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

    const dataError = new TypeError('Data must be an object')
    assert.throws(() => context.run(null, TIMEOUT), dataError)
    assert.throws(() => context.run('', TIMEOUT), dataError)
    assert.throws(() => context.run(42, TIMEOUT), dataError)
    assert.throws(() => context.run([], TIMEOUT), dataError)
    assert.throws(() => context.run(() => {}, TIMEOUT), dataError)

    const numberError = new TypeError('Timeout argument must be a number')
    assert.throws(() => context.run({}, ''), numberError)

    const greaterError = new TypeError('Timeout argument must be greater than 0')
    assert.throws(() => context.run({
      'server.request.headers.no_cookies': 'value_attack'
    }, -1), greaterError)
    assert.throws(() => context.run({
      'server.request.headers.no_cookies': 'value_attack'
    }, 0), greaterError)
  })

  it('should collect result attributes information when a rule match', () => {
    const waf = new DDWAF(processor, 'processor_rules')

    const context = waf.createContext()

    assert(waf.diagnostics.processors.loaded.includes('processor-001'))
    assert.equal(waf.diagnostics.processors.failed.length, 0)

    const result = context.run({
      'server.request.body': 'value',
      'waf.context.processor': {
        'extract-schema': true
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
      'server.request.body': '',
      'waf.context.processor': {
        'extract-schema': true
      }
    }, TIMEOUT)

    // libddwaf 2.1 returns DDWAF_MATCH for attributes alone; that is not an attack.
    assertAbsent(result, 'status')
    assertAbsent(result, 'events')
    assertAbsent(result, 'actions')
    assert.deepStrictEqual(result.attributes, { 'server.request.body.schema': [8] })
    assert.strictEqual(result.keep, false)

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
      'server.request.body': ''
    }, TIMEOUT)

    assert.strictEqual(result.attributes, undefined)

    result = context.run({
      'server.request.body': '',
      'waf.context.processor': {
        'extract-schema': true
      }
    }, TIMEOUT)

    assert.deepStrictEqual(result.attributes, { 'server.request.body.schema': [8] })

    result = context.run({
      'server.request.query': ''
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
      'server.request.headers.no_cookies': 'normal_value'
    }, TIMEOUT)

    assert.strictEqual(result.timeout, false)
    assert.strictEqual(typeof result.keep, 'boolean')
    assert.strictEqual(result.keep, false)

    // Match result
    result = context.run({
      'server.request.headers.no_cookies': 'value_attack'
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
        custom_value_attack: 'match'
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
        custom_value_attack: 'match'
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

    it('should report actions without status or events when the matching rule disables events', () => {
      const silentActionRules = {
        version: '2.2',
        metadata: {
          rules_version: '1.0.0'
        },
        actions: [{
          id: 'silentblock',
          type: 'block_request',
          parameters: {
            status_code: '403',
            grpc_status_code: '10',
            type: 'auto'
          }
        }],
        rules: [{
          id: 'silent_action_rule',
          name: 'Action and attributes without event',
          tags: {
            type: 'silent_action',
            category: 'attack_attempt'
          },
          conditions: [{
            operator: 'phrase_match',
            parameters: {
              inputs: [
                { address: 'silent_value_attack' }
              ],
              list: ['silent']
            }
          }],
          output: {
            event: false,
            keep: true,
            attributes: {
              '_dd.appsec.trace.silent': { value: 'silent' }
            }
          },
          on_match: ['silentblock']
        }]
      }

      const waf = new DDWAF(silentActionRules, 'silent_action_ruleset')
      let context

      try {
        assert.deepStrictEqual(waf.diagnostics.rules.loaded, ['silent_action_rule'])

        context = waf.createContext()
        const result = context.run({
          silent_value_attack: 'silent'
        }, TIMEOUT)

        assert.strictEqual(result.timeout, false)
        assertAbsent(result, 'status')
        assertAbsent(result, 'events')
        assert.strictEqual(typeof result.actions.block_request.security_response_id, 'string')
        assert.deepStrictEqual(result.actions, {
          block_request: {
            security_response_id: result.actions.block_request.security_response_id,
            grpc_status_code: 10,
            status_code: 403,
            type: 'auto'
          }
        })
        assert.deepStrictEqual(result.attributes, { '_dd.appsec.trace.silent': 'silent' })
        assert.strictEqual(result.keep, true)
      } finally {
        if (context) context.dispose()
        waf.dispose()
      }
    })
  })
})

describe('Handle errors', () => {
  it('should handle invalid arguments number', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    try {
      context.run({})
    } catch (e) {
      assert.strictEqual(e.message, 'Wrong number of arguments, 2 expected')
    }
  })

  it('should handle invalid timeout arguments', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    try {
      context.run({}, 'TIMEOUT')
    } catch (e) {
      assert.strictEqual(e.message, 'Timeout argument must be a number')
    }

    try {
      context.run({}, 0)
    } catch (e) {
      assert.strictEqual(e.message, 'Timeout argument must be greater than 0')
    }
  })

  it('should handle invalid arguments', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    assert.throws(
      () => context.run('invalid_object', TIMEOUT),
      new TypeError('Data must be an object')
    )
  })
})
