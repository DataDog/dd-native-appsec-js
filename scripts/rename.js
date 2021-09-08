'use strict'
const path = require('path')
const fs = require('fs')

const pkg = require('../package.json')
pkg.name = pkg.name + '-test'

const dirContent = fs.readdirSync(path.join(__dirname, '..'))
const tarball = dirContent.find((x) => x.startsWith('datadog-native-appsec-') && x.endsWith('.tgz'))
if (!tarball) {
  throw new Error('this script must run in CI only')
}

fs.writeFileSync(path.join(__dirname, '..', 'package.json'), JSON.stringify(pkg, null, 2))
fs.renameSync(path.join(__dirname, '..', tarball), path.join(__dirname, '..', 'datadog-native-appsec-0.0.0.tgz'))
fs.writeFileSync(path.join(__dirname, '..', 'index.js'), `'use strict'
module.exports = require('@datadog/native-appsec')
`)
