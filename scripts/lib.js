'use strict'
const path = require('path')
const os = require('os')
// FIXME(vdeturckheim)
module.exports.include = path.join(__dirname, '..', 'libddwaf-1.0.6-Darwin-x86_64-2efc246', 'include')
module.exports.lib = path.join(__dirname, '..', 'libddwaf-1.0.6-Darwin-x86_64-2efc246', 'lib', 'libddwaf.a')
