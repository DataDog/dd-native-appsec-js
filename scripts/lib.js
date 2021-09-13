/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
'use strict'
const path = require('path')
const os = require('os')
const pkg = require('../package.json')
const detectLib = require('detect-libc')

const platform = process.env.PLATFORM || os.platform()
const arch = process.env.ARCH || os.arch()
const libC = process.env.LIBC || detectLib.family
let libName = 'libddwaf.a'

const getLinuxDirname = function () {
  let archPart = ''
  if (arch === 'x64') {
    if (libC === detectLib.GLIBC) {
      archPart = 'x86_64-glibc'
    }
    if (libC === detectLib.MUSL) {
      archPart = 'x86_64-muslc'
    }
  }
  if (arch === 'arm64') {
    if (libC !== detectLib.GLIBC) {
      throw new Error(`Platform: ${platform} - ${arch} - ${libC || 'unknown'} is unsupported`)
    }
    archPart = 'aarch64'
  }
  if (!archPart) {
    throw new Error(`Platform: ${platform} - ${arch} - ${libC || 'unknown'} is unsupported`)
  }
  return `libddwaf-${pkg.libddwaf_version}-linux-${archPart}`
}

const getDirName = module.exports.getDirName = function () {
  // TODO: override arch to download binaries out of docker and copy them then
  switch (platform) {
    case 'darwin':
      return `libddwaf-${pkg.libddwaf_version}-darwin-x86_64`
    case 'win32':
      libName = 'ddwaf.lib'
      if (arch === 'x64') {
        return `libddwaf-${pkg.libddwaf_version}-windows-x64`
      }
      if (arch === 'ia32') {
        return `libddwaf-${pkg.libddwaf_version}-windows-win32`
      }
      break
    case 'linux':
      return getLinuxDirname()
  }
  throw new Error(`Platform: ${platform} - ${arch} - ${libC || 'unknown'} is unsupported`)
}

const dirname = getDirName()

module.exports.include = path.join(__dirname, '..', dirname, 'include').split('\\').join('\\\\')
module.exports.lib = path.join(__dirname, '..', dirname, 'lib', libName).split('\\').join('\\\\')

// console.log(module.exports);
