const crypto = require('crypto')
const { it, describe } = require('mocha')
const assert = require('assert')

const { DDWAF } = require('..')
const rules = require('./rules.json')

const blns = require('./blns/blns.json')

const waf = new DDWAF(rules)

const TIMEOUT = 20000

const ENCODINGS = [ // from https://github.com/nodejs/node/blob/master/lib/buffer.js
  'utf8',
  'ucs2',
  'utf16le',
  'latin1',
  'ascii',
  'base64',
  'base64url',
  'hex'
]

const test = function (entry) {
  const context = waf.createContext()
  const r1 = context.run({
    key: entry
  }, TIMEOUT)
  assert(r1 !== null)
  const r2 = context.run({
    [entry]: 'value'
  }, TIMEOUT)
  assert(r2 !== null)
  context.dispose()
}

describe('BLNS', () => {
  for (let i = 0; i < blns.length; ++i) {
    const str = blns[i]
    it(`should run blns entry #${i}`, () => {
      test(str)
    })
  }
})

describe('random strings', () => {
  for (let i = 0; i < 5000; ++i) {
    const buff = Buffer.alloc(10)
    crypto.randomFillSync(buff)
    for (const encoding of ENCODINGS) {
      const str = buff.toString(encoding)
      it(`should handle the string ${str}`, () => {
        test(str)
      })
    }
  }
})
