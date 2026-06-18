/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
'use strict'
const fs = require('fs')
const path = require('path')
const os = require('os')
const { libPath, libName, libDir, libFile } = require('./lib')

const platform = os.platform()
const arch = process.env.ARCH || os.arch()
const libc = process.env.LIBC || ''

const prebuildDir = path.join(__dirname, '..', 'prebuilds', `${platform}${libc}-${arch}`)
const runtimeLibPath = path.join(libDir, libFile)

if (fs.existsSync(prebuildDir)) {
  // Copy the runtime library next to the addon so rpath/@loader_path or loader can find it
  // - linux: libddwaf.so
  // - darwin: libddwaf.dylib
  // - win32: ddwaf.dll
  if (fs.existsSync(runtimeLibPath)) {
    fs.copyFileSync(runtimeLibPath, path.join(prebuildDir, libFile))
  }

  // Ensure link-time library is also available on linux (same as runtime) for completeness
  if (platform === 'linux' && fs.existsSync(libPath)) {
    fs.copyFileSync(libPath, path.join(prebuildDir, libName))
  }
}
