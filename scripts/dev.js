'use strict'
const fs = require('fs')
const path = require('path')
const os = require('os')
const detectLibc = require('detect-libc')

fs.mkdirSync(path.join(__dirname, '..', 'vendor',
  `${os.platform()}-${os.arch()}-${detectLibc.family || 'unknown'}`).split('\\').join('\\\\'), { recursive: true })
fs.copyFileSync(
  path.join(__dirname, '..', 'build', 'Release', 'appsec.node').split('\\').join('\\\\'),
  path.join(__dirname, '..', 'vendor', `${os.platform()}-${os.arch()}-${detectLibc.family || 'unknown'}`
    , 'appsec.node').split('\\').join('\\\\')
)
