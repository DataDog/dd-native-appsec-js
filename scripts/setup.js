/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
'use strict'
// const assert = require('assert')
// const childProcess = require('child_process')
const fs = require('fs')
const path = require('path')
const tar = require('tar')

// const pkg = require('../package.json')

// const libddwafVersion = process.argv[2] || pkg.libddwaf_version

// only relevant if libddwaf repo is private
// assert(process.env.GH_TOKEN, 'GH_TOKEN must be set')

const libddwafFolder = path.join(__dirname, '..', 'libddwaf')

// fs.mkdirSync(libddwafFolder, { recursive: true })

// childProcess.spawnSync('gh', [
//   'release', 'download',
//   '--repo', 'DataDog/libddwaf',
//   '--dir', libddwafFolder,
//   '--pattern', `libddwaf-${libddwafVersion}-*-linux-musl.tar.gz`,
//   '--pattern', `libddwaf-${libddwafVersion}-darwin-*.tar.gz`,
//   '--pattern', `libddwaf-${libddwafVersion}-windows-*.tar.gz`,
//   libddwafVersion
// ])

for (const name of fs.readdirSync(libddwafFolder)) {
  const file = path.join(libddwafFolder, name)
  tar.x({ file, cwd: libddwafFolder, sync: true })

  fs.rmSync(file)
}

for (const name of fs.readdirSync(libddwafFolder)) {
  const newDir = path.join(libddwafFolder, name)
  const renamedDir = newDir.substring(0, newDir.indexOf('-c03e4f9'))
  fs.renameSync(newDir, renamedDir)
}
