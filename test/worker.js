'use strict'

const { isMainThread, parentPort } = require('worker_threads')

if (!isMainThread) {
  const { DDWAF } = require('..')
  const rules = require('./rules.json')

  const waf = new DDWAF(rules)
  const context = waf.createContext()

  const result = context.run({
    persistent: {
      value_attack: 'whatev'
    }
  }, 1e9)

  parentPort.postMessage(result)

  context.dispose()
  waf.dispose()
}
