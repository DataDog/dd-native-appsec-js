const { it, describe } = require('mocha')

const assert = require('assert')
const crypto = require('crypto')

const { DDWAF } = require('..')
const rules = require('./rules.json')

const blns = require('./blns.json')

const TIMEOUT = 9999e3

const waf = new DDWAF(rules, 'recommended')

const ENCODINGS = [ // from https://github.com/nodejs/node/blob/master/lib/buffer.js
  'utf8',
  'ucs2',
  'utf16le',
  'latin1',
  'ascii',
  'base64',
  'base64url',
  'hex'
].filter((encoding) => {
  try {
    Buffer.from('hello', encoding)
    return true
  } catch (_) {
    return false
  }
})

function test (buff, encoding = 'utf8') {
  const str = buff.toString(encoding)
  const context = waf.createContext()

  const r1 = context.run({ persistent: { value_attack: str } }, TIMEOUT)
  assert(r1 && r1.events, `Expected to handle string value 0x${buff.toString('hex')} in ${encoding}`)

  const payload = { persistent: { key_attack: { [str]: '' } } }

  console.log(JSON.stringify(payload))

  const r2 = context.run(payload, TIMEOUT)
  assert(r2 && r2.events, `Expected to handle string key 0x${buff.toString('hex')} in ${encoding}`)

  context.dispose()
}

describe('fuzzing', () => {
  return
  it('should hanlde BLNS', () => {
    for (let i = 0; i < blns.length; ++i) {
      const buff = Buffer.from(blns[i], 'utf8')
      test(buff)
    }
  }).timeout(5000)

  it('should handle random strings', () => {
    for (let i = 0; i < 1000; ++i) {
      const buff = Buffer.alloc(10)
      crypto.randomFillSync(buff)

      for (const encoding of ENCODINGS) {
        test(buff, encoding)
      }
    }
  }).timeout(5000)
})


it('should test this shit', () => {
  test(Buffer.from([0x80, 0xcf, 0x51, 0xdb, 0x8f, 0x1b, 0x47, 0xe4, 0xdd, 0xb6]))
})