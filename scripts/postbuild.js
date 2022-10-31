/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
'use strict'
const fs = require('fs')
const path = require('path')
const os = require('os')
const Lib = require('./lib')

const platform = os.platform()
const arch = process.env.ARCH || os.arch()
const libc = process.env.LIBC || ''

const prebuildDir = path.join(__dirname, '..', 'prebuilds', `${platform}${libc}-${arch}`)
const filename = Lib.getLibName().split('\\').join('\\\\')

if (platform === 'linux' && fs.existsSync(prebuildDir)) {
  fs.copyFileSync(Lib.lib, path.join(prebuildDir, filename))
}
