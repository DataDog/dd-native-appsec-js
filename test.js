'use strict'
const rules = require('./rules.json')
const { DDWAF } = require('./build/Release/appsec.node')

console.log(DDWAF.version())
const instance = new DDWAF(rules)

const context = instance.createContext()

console.log(context.disposed)

console.log(context.run({}, 1000))
console.log(context.dispose())
console.log(context.disposed)
