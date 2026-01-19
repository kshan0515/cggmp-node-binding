const { existsSync } = require('fs')
const { join } = require('path')

const { platform, arch } = process

let nativeBinding = null
let localBind = join(__dirname, 'cggmp-node.node')

if (existsSync(localBind)) {
  nativeBinding = require(localBind)
} else {
  // 폴백 로직 (필요시 추가)
  throw new Error(`Failed to load native binding from ${localBind}`)
}

module.exports = nativeBinding