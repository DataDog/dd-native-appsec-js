/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
'use strict'
const fs = require('fs')
const path = require('path')
const os = require('os')
const detectLibc = require('detect-libc')

fs.mkdirSync(path.join(__dirname, '..', 'vendor',
  `${os.platform()}-${os.arch()}-${detectLibc.family || 'unknown'}`).split('\\').join('\\\\'), { recursive: true })
fs.copyFileSync(
  path.join(__dirname, '..', 'build', 'Release', 'appsec.node').split('\\').join('\\\\'),
  path.join(__dirname, '..', 'vendor', `${os.platform()}-${os.arch()}-${detectLibc.family || 'unknown'}`
    , 'appsec.node').split('\\').join('\\\\')
)
