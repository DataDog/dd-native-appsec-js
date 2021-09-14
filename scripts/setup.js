/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
'use strict'
const assert = require('assert')
const childProcess = require('child_process')
const fs = require('fs')

const tar = require('tar')

const pkg = require('../package.json')
const lib = require('./lib')
const path = require('path')

assert(process.env.GH_TOKEN, 'GH_TOKEN must be set') // TODO: remove when libddwaf is open sourced

async function download () {
  const dir = lib.getDirName()
  childProcess.spawnSync('gh', ['release', 'download', '--repo', 'DataDog/libddwaf',
    '-p', `${dir}.tar.gz`, pkg.libddwaf_version])
  await tar.x({
    file: `${lib.getDirName()}.tar.gz`
  })
  const file = fs.readdirSync(process.cwd()).find((x) => x.startsWith(dir))
  fs.renameSync(file, dir)
  const libName = fs.readdirSync(path.join(process.cwd(), dir))
  if (libName.includes('lib64')) {
    fs.renameSync(path.join(process.cwd(), dir, 'lib64'), path.join(process.cwd(), dir, 'lib'))
  }
}

download()
  .catch((e) => {
    // eslint-disable-next-line
    console.error(e)
    process.exit(1)
  })
