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
  it('should not persist subcontext data into its parent context', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    const subcontext = context.createSubcontext()
    const subResult = subcontext.run({
      'server.request.headers.no_cookies': 'value_ATTack'
    }, TIMEOUT)
    assert.strictEqual(subResult.status, 'match')
    subcontext.dispose()

    // A persisted address would not match twice, so a second match proves it.
    const result = context.run({
      'server.request.headers.no_cookies': 'value_ATTack'
    }, TIMEOUT)
    assert.strictEqual(result.status, 'match')

    context.dispose()
    waf.dispose()
  })

  describe('subcontext inheritance', () => {
    // A rule needing one address from the parent and one from the subcontext is
    // the only way to prove inheritance: a rule the subcontext can satisfy on
    // its own would pass even with no inheritance at all.
    const twoAddressRules = {
      version: '2.2',
      metadata: { rules_version: '1.0.0' },
      rules: [{
        id: 'needs-both-addresses',
        name: 'needs both addresses',
        tags: { type: 'test', category: 'test' },
        conditions: [
          {
            operator: 'match_regex',
            parameters: { inputs: [{ address: 'server.request.headers.no_cookies' }], regex: 'PARENTVAL' }
          },
          {
            operator: 'match_regex',
            parameters: { inputs: [{ address: 'server.io.net.url' }], regex: 'SUBVAL' }
          }
        ],
        transformers: []
      }]
    }
    const PARENT_DATA = { 'server.request.headers.no_cookies': 'PARENTVAL' }
    const SUB_DATA = { 'server.io.net.url': 'http://SUBVAL/' }

    it('should evaluate parent context data from a subcontext', () => {
      const waf = new DDWAF(twoAddressRules, 'two-address')
      const context = waf.createContext()

      context.run(PARENT_DATA, TIMEOUT)
      const subcontext = context.createSubcontext()
      const result = subcontext.run(SUB_DATA, TIMEOUT)

      assert.strictEqual(result.status, 'match')

      subcontext.dispose()
      context.dispose()
      waf.dispose()
    })

    // A subcontext snapshots the parent store when it is created, so it must be
    // created after the data it needs to see has been evaluated on the parent.
    it('should not see parent data added after the subcontext was created', () => {
      const waf = new DDWAF(twoAddressRules, 'two-address')
      const context = waf.createContext()

      const subcontext = context.createSubcontext()
      context.run(PARENT_DATA, TIMEOUT)
      const result = subcontext.run(SUB_DATA, TIMEOUT)

      assert.notStrictEqual(result.status, 'match')

      subcontext.dispose()
      context.dispose()
      waf.dispose()
    })

    it('should not leak subcontext data into the parent context', () => {
      const waf = new DDWAF(twoAddressRules, 'two-address')
      const context = waf.createContext()

      const subcontext = context.createSubcontext()
      subcontext.run(SUB_DATA, TIMEOUT)
      subcontext.dispose()

      const result = context.run(PARENT_DATA, TIMEOUT)
      assert.notStrictEqual(result.status, 'match')

      context.dispose()
      waf.dispose()
    })
  })

  it('should keep a subcontext usable after its parent context is disposed', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()
    const subcontext = context.createSubcontext()

    context.dispose()

    const result = subcontext.run({
      'server.request.headers.no_cookies': 'value_ATTack'
    }, TIMEOUT)
    assert.strictEqual(result.status, 'match')

    subcontext.dispose()
    waf.dispose()
  })

  it('should throw when using a disposed subcontext or context', () => {
    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()
    const subcontext = context.createSubcontext()

    subcontext.dispose()
    assert.throws(
      () => subcontext.run({ 'server.request.headers.no_cookies': 'value_ATTack' }, TIMEOUT),
      new Error('Calling run on a disposed subcontext')
    )

    context.dispose()
    assert.throws(
      () => context.createSubcontext(),
      new Error('Calling createSubcontext on a disposed context')
    )

    waf.dispose()
  })
})

describe('subcontext scale', () => {
  const ATTACK = { 'server.request.headers.no_cookies': 'value_ATTack' }
  const SUBCONTEXTS = 20000

  const churn = (context, n) => {
    let matched = 0
    for (let i = 0; i < n; i++) {
      const subcontext = context.createSubcontext()
      if (subcontext.run(ATTACK, TIMEOUT).status === 'match') matched++
      subcontext.dispose()
    }
    return matched
  }

  it('should stay correct across many sequential subcontexts', function () {
    this.timeout(60000)

    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    assert.strictEqual(churn(context, SUBCONTEXTS), SUBCONTEXTS)

    // The parent must be unaffected by the churn: none of that data persisted.
    assert.strictEqual(context.run(ATTACK, TIMEOUT).status, 'match')

    context.dispose()
    waf.dispose()
  })

  it('should keep many concurrently live subcontexts usable', function () {
    this.timeout(60000)

    const waf = new DDWAF(rules, 'recommended')
    const context = waf.createContext()

    const subcontexts = []
    for (let i = 0; i < 5000; i++) subcontexts.push(context.createSubcontext())

    let matched = 0
    for (const subcontext of subcontexts) {
      if (subcontext.run(ATTACK, TIMEOUT).status === 'match') matched++
    }
    assert.strictEqual(matched, subcontexts.length)

    // Subcontexts are independently owned, so disposing the parent first is legal.
    context.dispose()
    for (const subcontext of subcontexts) {
      subcontext.dispose()
      assert(subcontext.disposed)
    }

    waf.dispose()
  })
})
