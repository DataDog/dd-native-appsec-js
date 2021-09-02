'use strict'
const os = require('os')
const detectLibc = require('detect-libc')

const getDir = module.exports.getDir = function () {
  return `${os.platform()}-${os.arch()}-${detectLibc.family || 'unknown'}`
}

module.exports.load = function () {
  return require(`../vendor/${getDir()}/appsec.node`)
}
