'use strict'

const {
  Worker,
  isMainThread,
  parentPort
} = require('worker_threads')
const { DDWAF } = require('..')
const rules = require('./rules.json')

if (isMainThread) {
  const { describe, it } = require('mocha')

  describe('worker threads', () => {
    it('DDWAF does not crash with worker threads', (done) => {
      const waf = new DDWAF(rules)
      const worker = new Worker(__filename)

      worker.on('message', msg => {
        const ip = '123.123.123.123'
        const payload = {
          persistent: {
            'http.client_ip': ip
          }
        }

        const context = waf.createContext()
        context.run(payload, 9999e3)
        context.dispose()

        done()
      })
    })
  })
} else {
  parentPort.postMessage('started')
}
