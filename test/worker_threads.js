'use strict'

const { describe, it } = require('mocha')
const assert = require('assert')

const path = require('path')
const { Worker } = require('worker_threads')

const { DDWAF } = require('..')
const rules = require('./rules.json')

const WORKER_PATH = path.join(__dirname, 'worker.js')

describe('worker threads', () => {
  it('should not crash when worker created after DDWAF', (done) => {
    const waf = new DDWAF(rules)
    const context = waf.createContext()

    const result1 = context.run({
      persistent: {
        value_attack: 'whatev'
      }
    }, 1e9)
    assert.strictEqual(result1?.status, 'match')

    const worker = new Worker(WORKER_PATH)

    worker.on('message', (result2) => {
      assert.strictEqual(result2?.status, 'match')

      const result3 = context.run({
        persistent: {
          key_attack: { key: 'whatev' }
        }
      }, 1e9)
      assert.strictEqual(result3?.status, 'match')

      context.dispose()
      waf.dispose()
      done()
    })
  })

  it('should not crash when worker created before DDWAF', (done) => {
    const worker = new Worker(WORKER_PATH)

    worker.on('message', (result1) => {
      assert.strictEqual(result1?.status, 'match')

      const waf = new DDWAF(rules)
      const context = waf.createContext()

      const result2 = context.run({
        persistent: {
          value_attack: 'whatev'
        }
      }, 1e9)
      assert.strictEqual(result2?.status, 'match')

      context.dispose()
      waf.dispose()
      done()
    })
  })
})
