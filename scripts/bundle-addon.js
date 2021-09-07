'use strict'
const path = require('path')
const os = require('os')
const fs = require('fs')
const tar = require('tar')
const detectLib = require('detect-libc')
const { getDirName } = require('./lib')

async function bundleAddon () {
  const files = ['appsec.node']
  if (os.platform() === 'win32') {
    fs.renameSync(path.join(__dirname, '..', getDirName(), 'lib', 'ddwaf.dll'),
      path.join(__dirname, '..', 'build', 'Release', 'ddwaf.dll'))
    files.push('ddwaf.dll')
  }

  await tar.c({
    cwd: path.join(__dirname, '..', 'build', 'Release'),
    file: `${os.platform()}-${os.arch()}-${detectLib.family || 'unknown'}.tgz`,
    gzip: true
  },
  files
  )
}

bundleAddon().catch((e) => {
  // console.error(e)
  process.exit(1)
})
