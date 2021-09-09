'use strict'
const path = require('path')
const os = require('os')
const pkg = require('../package.json')
const detectLib = require('detect-libc')

const platform = process.env.PLATFORM || os.platform()
const arch = process.env.ARCH || os.arch()
const libC = process.env.LIBC || detectLib.family
let libName = 'libddwaf.a'
const getDirName = module.exports.getDirName = function () {
  // TODO: override arch to download binaries out of docker and copy them then
  switch (platform) {
    case 'darwin':
      return `libddwaf-${pkg.libddwaf_version}-Darwin-x86_64`
    case 'win32':
      libName = 'ddwaf.lib'
      if (arch === 'x64') {
        return `libddwaf-${pkg.libddwaf_version}-Windows-x64`
      }
      if (arch === 'x32') {
        return `libddwaf-${pkg.libddwaf_version}-windows-win32.tar.gz`
      }
      break
    case 'linux':
      if (libC === detectLib.GLIBC) {
        return `libddwaf-${pkg.libddwaf_version}-Linux-x86_64-glibc`
      }
      if (libC === detectLib.MUSL) {
        return `libddwaf-${pkg.libddwaf_version}-Linux-x86_64-muslc`
      }
      break
  }
  throw new Error(`Platform: ${platform} - ${arch} is unsupported`)
}

const dirname = getDirName()

module.exports.include = path.join(__dirname, '..', dirname, 'include').split('\\').join('\\\\')
module.exports.lib = path.join(__dirname, '..', dirname, 'lib', libName).split('\\').join('\\\\')

// console.log(module.exports);
