/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
'use strict'
const path = require('path')
const os = require('os')
const fs = require('fs')
const tar = require('tar')
const detectLib = require('detect-libc')

const Lib = require('./lib')

async function bundleAddon () {
  const files = ['appsec.node']

  if (os.platform() === 'linux') {
    fs.copyFileSync(
      Lib.lib,
      path.join(__dirname, '..', 'build', 'Release', Lib.getLibName()).split('\\').join('\\\\')
    )
    files.push(Lib.getLibName())
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
  // eslint-disable-next-line
  console.error(e)
  process.exit(1)
})
