/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
'use strict'
// const assert = require('assert')
const childProcess = require('child_process')
const fs = require('fs')
const path = require('path')
const tar = require('tar')

const pkg = require('../package.json')

// only relevant if libddwaf repo is private
// assert(process.env.GH_TOKEN, 'GH_TOKEN must be set')

fs.mkdirSync('libddwaf', { recursive: true })

childProcess.spawnSync('gh', ['release', 'download', '--repo', 'DataDog/libddwaf',
  '-D', 'libddwaf', '-p', 'libddwaf-*', pkg.libddwaf_version])

const archives = fs.readdirSync('libddwaf')
  .filter(name => name.endsWith('.tar.gz'))
  .map(name => path.join('libddwaf', name))

for (const file of archives) {
  tar.x({ file, cwd: 'libddwaf', sync: true })
  fs.rmSync(file)
}
