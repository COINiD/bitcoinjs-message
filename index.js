var secp256k1 = require('secp256k1')
var varuint = require('varuint-bitcoin')
var bitcoin = require('bitcoinjs-lib')
var bufferEquals = require('buffer-equals')

function encodeSignature (signature, recovery, compressed) {
  if (compressed) recovery += 4
  return Buffer.concat([Buffer.alloc(1, recovery + 27), signature])
}

function decodeSignature (buffer) {
  if (buffer.length !== 65) throw new Error('Invalid signature length')

  var flagByte = buffer.readUInt8(0) - 27
  if (flagByte > 7) throw new Error('Invalid signature parameter')

  return {
    compressed: !!(flagByte & 4),
    recovery: flagByte & 3,
    signature: buffer.slice(1)
  }
}

function magicHash (message, network) {
  var messagePrefix = network.messagePrefix || '\u0018Bitcoin Signed Message:\n'
  if (!Buffer.isBuffer(messagePrefix)) messagePrefix = Buffer.from(messagePrefix, 'utf8')

  var messageVISize = varuint.encodingLength(message.length)
  var buffer = Buffer.allocUnsafe(messagePrefix.length + messageVISize + message.length)
  messagePrefix.copy(buffer, 0)
  varuint.encode(message.length, buffer, messagePrefix.length)
  buffer.write(message, messagePrefix.length + messageVISize)
  return network.hashFunctions.message(buffer)
}

function sign (message, privateKey, compressed, network) {
  var hash = magicHash(message, network)
  var sigObj = secp256k1.sign(hash, privateKey)
  return encodeSignature(sigObj.signature, sigObj.recovery, compressed)
}

function doesPubKeyBelongToAddress (pubKey, address, network) {
  const getForPubKeyHash = () => bitcoin.crypto.hash160(pubKey)
  const getForScriptHash = () => bitcoin.crypto.hash160(bitcoin.script.witnessPubKeyHash.output.encode(bitcoin.crypto.hash160(pubKey)))

  let decode
  try {
    decode = bitcoin.address.fromBase58Check(address, network)
  } catch (e) {}

  if (decode) {
    if (decode.version === network.pubKeyHash) {
      return bufferEquals(getForPubKeyHash(), decode.hash)
    }
    if (decode.version === network.scriptHash) {
      return bufferEquals(getForScriptHash(), decode.hash)
    }
  }

  try {
    decode = bitcoin.address.fromBech32(address)
  } catch (e) {}

  if (decode) {
    if (decode.prefix !== network.bech32) throw new Error(address + ' has an invalid prefix')

    if (decode.version === 0) {
      if (decode.data.length === 20) {
        return bufferEquals(getForPubKeyHash(), decode.data)
      }
      if (decode.data.length === 32) {
        return bufferEquals(getForScriptHash(), decode.data)
      }
    }
  }

  throw new Error(address + ' could not be decoded')
}

function verify (message, address, signature, network) {
  if (network === undefined) network = bitcoin.networks.bitcoin
  if (!Buffer.isBuffer(signature)) signature = Buffer.from(signature, 'base64')

  var parsed = decodeSignature(signature)
  var hash = magicHash(message, network)
  var pubKey = secp256k1.recover(hash, parsed.signature, parsed.recovery, parsed.compressed)

  return doesPubKeyBelongToAddress(pubKey, address, network)
}

module.exports = {
  magicHash: magicHash,
  sign: sign,
  verify: verify
}
