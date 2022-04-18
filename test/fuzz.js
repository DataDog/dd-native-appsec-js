const crypto = require('crypto')
const { it, describe } = require('mocha')
const assert = require('assert')

const { DDWAF } = require('..')
const rules = require('./rules.json')

const blns = require('./blns/blns.json')

const waf = new DDWAF(rules)

const TIMEOUT = 9999e3

const ENCODINGS_0 = [ // from https://github.com/nodejs/node/blob/master/lib/buffer.js
  'utf8',
  'ucs2',
  'utf16le',
  'latin1',
  'ascii',
  'base64',
  'base64url',
  'hex'
]
const ENCODINGS = []
for (const encoding of ENCODINGS_0) {
  try {
    Buffer.from('hello', encoding)
    ENCODINGS.push(encoding)
  } catch (_) {
  }
}

const test = function (entry, encoding = 'utf8') {
  const context = waf.createContext()
  const r1 = context.run({
    atk: entry
  }, TIMEOUT)
  assert(r1)
  assert(!r1.timeout)
  assert(r1.data)
  // FIXME: there is a reporting issue with alternative encodings
  // const actual = Buffer.from(JSON.parse(r1.data)[0].rule_matches[0].parameters[0].value, encoding);
  // const expected = Buffer.from(entry, encoding);
  // assert.strictEqual(Buffer.compare(actual, expected), 0)
  const r2 = context.run({
    [entry]: 'value'
  }, TIMEOUT)
  assert(r2)
  assert(!r2.timeout)
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
      it(`should handle the string 0x${buff.toString('hex')} in ${encoding}`, () => {
        test(str)
      })
    }
  }
})
