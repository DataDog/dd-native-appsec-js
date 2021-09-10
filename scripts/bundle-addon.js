'use strict'
const path = require('path')
const os = require('os')
const tar = require('tar')
const detectLib = require('detect-libc')

async function bundleAddon () {
  const files = ['appsec.node']

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
