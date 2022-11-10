/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
'use strict'
const path = require('path')
const os = require('os')
const pkg = require('../package.json')

const platform = process.env.PLATFORM || os.platform()
const arch = process.env.ARCH || os.arch()

const libNames = {
  darwin: 'libddwaf.a',
  win32: 'ddwaf_static.lib',
  linux: 'libddwaf.so'
}

const dirNames = {
  darwin: {
    arm64: 'darwin-arm64',
    x64: 'darwin-x86_64'
  },
  win32: {
    x64: 'windows-x64',
    ia32: 'windows-win32'
  },
  linux: {
    arm64: 'linux-aarch64',
    x64: 'linux-x86_64'
  }
}

function getDirName () {
  const name = dirNames[platform] && dirNames[platform][arch]

  if (!name) throw new Error(`Platform: ${platform} - ${arch} is unsupported`)

  return `libddwaf-${pkg.libddwaf_version}-${name}`
}

const dirname = getDirName()
const libName = libNames[platform]
const basename = path.join(__dirname, '..', 'libddwaf', dirname)

module.exports = {
  includePath: path.join(basename, 'include').split('\\').join('\\\\'),
  libPath: path.join(basename, 'lib', libName).split('\\').join('\\\\'),
  libName
}
