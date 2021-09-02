'use strict'
const tar = require('tar')
const fs = require('fs')
const path = require('path')
const { getDir } = require('../lib/loader')

// TODO: test on windows
async function install () {
  const dir = getDir()
  const tarPAth = path.join(__dirname, '..', 'vendor', dir + '.tgz').split('\\').join('\\\\')
  if (!fs.existsSync(tarPAth)) {
    // console.error(`No support for ${dir}`)
    process.exit(0)
  }
  await tar.x({
    file: tarPAth
  })
  fs.mkdirSync(path.join(__dirname, '..', 'vendor', dir), { recursive: true })
  fs.renameSync(path.join(__dirname, 'appsec.node').split('\\').join('\\\\')
    , path.join(__dirname, '..', 'vendor', dir, 'appsec.node').split('\\').join('\\\\'))
  if (fs.existsSync(path.join(__dirname, 'ddwaf.dll').split('\\').join('\\\\'))) {
    fs.renameSync(path.join(__dirname, 'ddwaf.dll').split('\\').join('\\\\'),
      path.join(__dirname, '..', 'vendor', dir, 'ddwaf.dll').split('\\').join('\\\\'))
  }
  fs.writeFileSync(path.join(__dirname, '..', 'install.json').split('\\').join('\\\\')
    , JSON.stringify({ target: dir }, null, 2))
}

install()
  .catch((e) => {
    // console.error(e)
    process.exit(0)
  })
