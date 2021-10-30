const Crypto = require('crypto')
const { Readable, Transform } = require('stream')
const HKDF = require('futoin-hkdf')
const Jimp = require('jimp')
const { createReadStream, createWriteStream, promises, WriteStream} = require('fs')
const { exec } = require('child_process')
const {platform, release, tmpdir} = require('os')
const HttpsProxyAgent = require('https-proxy-agent')
const { URL } = require('url')
const { Agent } = require('https')
const Decoder = require('../Binary/Decoder')
const { MessageType, HKDFInfoKeys, MessageOptions, WAChat, WAMessageContent, BaileysError, WAMessageProto, TimedOutError, CancelledError, WAGenericMediaMessage, WAMessage, WAMessageKey, DEFAULT_ORIGIN, WAMediaUpload } = require('../Binary/Constants')
// const KeyedDB = require('@adiwajshing/keyed-db')
const got = require('got')
const { join } = require('path')
const { IAudioMetadata } = require('music-metadata')
const { once } = require('events')

browser = 'Safari'

const platformMap = {
    'aix': 'AIX',
    'darwin': 'Mac OS',
    'win32': 'Windows',
    'android': 'Android'
};
const Browsers = {
    ubuntu: ['Ubuntu', browser, '18.04'],
    macOS: ['Mac OS', browser, '10.15.3'],
    baileys: ['Baileys', browser, '3.0'],
    /** The appropriate browser based on your OS & release */
}
const toNumber = (t) => (t['low'] || t)
const waChatKey = (pin) => ({
    key: (c) => (pin ? (c.pin ? '1' : '0') : '') + (c.archive === 'true' ? '0' : '1') + c.t.toString(16).padStart(8, '0') + c.jid,
    compare: (k1, k2) => k2.localeCompare (k1)
})
const waMessageKey = {
    key: (m) => (5000 + (m['epoch'] || 0)).toString(16).padStart(6, '0') + toNumber(m.messageTimestamp).toString(16).padStart(8, '0'),
    compare: (k1, k2) => k1.localeCompare (k2)
}
const WA_MESSAGE_ID = (m) => GET_MESSAGE_ID (m.key)
const GET_MESSAGE_ID = (key) => `${key.id}|${key.fromMe ? 1 : 0}`

const whatsappID = (jid) => jid?.replace ('@c.us', '@s.whatsapp.net')
const isGroupID = (jid) => jid?.endsWith ('@g.us')

const newMessagesDB = (messages = []) => {
    const db = new KeyedDB(waMessageKey, WA_MESSAGE_ID)
    messages.forEach(m => !db.get(WA_MESSAGE_ID(m)) && db.insert(m))
    return db
} 

function shallowChanges (old, current, {lookForDeletedKeys}) {
    let changes = {}
    for (let key in current) {
        if (old[key] !== current[key]) {
            changes[key] = current[key] || null
        }
    }
    if (lookForDeletedKeys) {
        for (let key in old) {
            if (!changes[key] && old[key] !== current[key]) {
                changes[key] = current[key] || null
            }
        }
    }
    return changes
}

/** decrypt AES 256 CBC; where the IV is prefixed to the buffer */
function aesDecrypt(buffer, key) {
    return aesDecryptWithIV(buffer.slice(16, buffer.length), key, buffer.slice(0, 16))
}
/** decrypt AES 256 CBC */
function aesDecryptWithIV(buffer, key, IV) {
    const aes = Crypto.createDecipheriv('aes-256-cbc', key, IV)
    return Buffer.concat([aes.update(buffer), aes.final()])
}
// encrypt AES 256 CBC; where a random IV is prefixed to the buffer
function aesEncrypt(buffer, key) {
    const IV = randomBytes(16)
    const aes = Crypto.createCipheriv('aes-256-cbc', key, IV)
    return Buffer.concat([IV, aes.update(buffer), aes.final()]) // prefix IV to the buffer
}
// encrypt AES 256 CBC with a given IV
function aesEncrypWithIV(buffer, key, IV) {
    const aes = Crypto.createCipheriv('aes-256-cbc', key, IV)
    return Buffer.concat([aes.update(buffer), aes.final()]) // prefix IV to the buffer
}
// sign HMAC using SHA 256
function hmacSign(buffer, key) {
    return Crypto.createHmac('sha256', key).update(buffer).digest()
}
function sha256(buffer) {
    return Crypto.createHash('sha256').update(buffer).digest()
}
// HKDF key expansion
function hkdf(buffer, expandedLength, info = null) {
    return HKDF(buffer, expandedLength, { salt: Buffer.alloc(32), info: info, hash: 'SHA-256' })
}
// generate a buffer with random bytes of the specified length
function randomBytes(length) {
    return Crypto.randomBytes(length)
}
/** unix timestamp of a date in seconds */
const unixTimestampSeconds = (date = new Date()) => Math.floor(date.getTime()/1000)

const debouncedTimeout = (intervalMs = 1000, task) => {
    let timeout
    return {
        start: (newIntervalMs, newTask) => {
            task = newTask || task
            intervalMs = newIntervalMs || intervalMs
            timeout && clearTimeout(timeout)
            timeout = setTimeout(task, intervalMs)
        },
        cancel: () => {
            timeout && clearTimeout(timeout)
            timeout = undefined
        },
        setTask: (newTask) => task = newTask,
        setInterval: (newInterval) => intervalMs = newInterval
    }
}

const delay = (ms) => delayCancellable (ms).delay
const delayCancellable = (ms) => {
    const stack = new Error().stack
    let timeout
    let reject
    const delay = new Promise((resolve, _reject) => {
        timeout = setTimeout(resolve, ms)
        reject = _reject
    })
    const cancel = () => {
        clearTimeout (timeout)
        reject (CancelledError(stack))
    }
    return { delay, cancel }
}
async function promiseTimeout(ms, promise) {
    if (!ms) return new Promise (promise)
    const stack = new Error().stack
    // Create a promise that rejects in <ms> milliseconds
    let {delay, cancel} = delayCancellable (ms) 
    const p = new Promise ((resolve, reject) => {
        delay
        .then(() => reject(TimedOutError(stack)))
        .catch (err => reject(err)) 
        
        promise (resolve, reject)
    })
    .finally (cancel)
    return p
}
// whatsapp requires a message tag for every message, we just use the timestamp as one
function generateMessageTag(epoch) {
    let tag = unixTimestampSeconds().toString()
    if (epoch) tag += '.--' + epoch // attach epoch if provided
    return tag
}
// generate a random 16 byte client ID
function generateClientID() {
    return randomBytes(16).toString('base64')
}
// generate a random 16 byte ID to attach to a message
function generateMessageID() {
    return '3EB0' + randomBytes(4).toString('hex').toUpperCase()
}
function decryptWA (message, macKey, encKey, decoder, fromMe=false) {
    let commaIndex = message.indexOf(',') // all whatsapp messages have a tag and a comma, followed by the actual message
    if (commaIndex < 0) throw new BaileysError ('invalid message', { message }) // if there was no comma, then this message must be not be valid
    
    if (message[commaIndex+1] === ',') commaIndex += 1
    let data = message.slice(commaIndex+1, message.length)
    
    // get the message tag.
    // If a query was done, the server will respond with the same message tag we sent the query with
    const messageTag = message.slice(0, commaIndex).toString()
    let json
    let tags
    if (data.length > 0) {
        if (typeof data === 'string') {
            json = JSON.parse(data) // parse the JSON
        } else {
            if (!macKey || !encKey) {
                throw new BaileysError ('recieved encrypted buffer when auth creds unavailable', { message })
            }
            /* 
                If the data recieved was not a JSON, then it must be an encrypted message.
                Such a message can only be decrypted if we're connected successfully to the servers & have encryption keys
            */
            if (fromMe) {
                tags = [data[0], data[1]]
                data = data.slice(2, data.length)
            }
            
            const checksum = data.slice(0, 32) // the first 32 bytes of the buffer are the HMAC sign of the message
            data = data.slice(32, data.length) // the actual message
            const computedChecksum = hmacSign(data, macKey) // compute the sign of the message we recieved using our macKey
            
            if (checksum.equals(computedChecksum)) {
                // the checksum the server sent, must match the one we computed for the message to be valid
                const decrypted = aesDecrypt(data, encKey) // decrypt using AES
                json = decoder.read(decrypted) // decode the binary message into a JSON array
            } else {
                throw new BaileysError ('checksum failed', {
                    received: checksum.toString('hex'),
                    computed: computedChecksum.toString('hex'),
                    data: data.slice(0, 80).toString(),
                    tag: messageTag,
                    message: message.slice(0, 80).toString()
                })
            }
        }   
    }
    return [messageTag, json, tags]
}
/** generates all the keys required to encrypt/decrypt & sign a media message */
function getMediaKeys(buffer, mediaType) {
    if (typeof buffer === 'string') {
        buffer = Buffer.from (buffer.replace('data:;base64,', ''), 'base64')
    }
    // expand using HKDF to 112 bytes, also pass in the relevant app info
    const expandedMediaKey = hkdf(buffer, 112, HKDFInfoKeys[mediaType])
    return {
        iv: expandedMediaKey.slice(0, 16),
        cipherKey: expandedMediaKey.slice(16, 48),
        macKey: expandedMediaKey.slice(48, 80),
    }
}
/** Extracts video thumb using FFMPEG */
const extractVideoThumb = async (
    path,
    destPath,
    time,
    size,
) =>
    new Promise((resolve, reject) => {
        const cmd = `ffmpeg -ss ${time} -i ${path} -y -s ${size.width}x${size.height} -vframes 1 -f image2 ${destPath}`
        exec(cmd, (err) => {
            if (err) reject(err)
            else resolve()
        })
    })

const compressImage = async (bufferOrFilePath) => {
    const jimp = await Jimp.read(bufferOrFilePath)
    const result = await jimp.resize(48, 48).getBufferAsync(Jimp.MIME_JPEG)
    return result
}
const generateProfilePicture = async (buffer) => {
    const jimp = await Jimp.read (buffer)
    const min = Math.min(jimp.getWidth (), jimp.getHeight ())
    const cropped = jimp.crop (0, 0, min, min)
    return {
        img: await cropped.resize(640, 640).getBufferAsync (Jimp.MIME_JPEG),
        preview: await cropped.resize(96, 96).getBufferAsync (Jimp.MIME_JPEG)
    }
}
const ProxyAgent = (host) => HttpsProxyAgent(host)
/** gets the SHA256 of the given media message */
const mediaMessageSHA256B64 = (message) => {
    const media = Object.values(message)[0]
    return media?.fileSha256 && Buffer.from(media.fileSha256).toString ('base64')
}
async function getAudioDuration (buffer) {
    const musicMetadata = await import ('music-metadata')
    let metadata
    if(Buffer.isBuffer(buffer)) {
        metadata = await musicMetadata.parseBuffer(buffer, null, { duration: true })
    } else {
        const rStream = createReadStream(buffer)
        metadata = await musicMetadata.parseStream(rStream, null, { duration: true })
        rStream.close()
    }
    return metadata.format.duration;
}
const toReadable = (buffer) => {
    const readable = new Readable({ read: () => {} })
    readable.push(buffer)
    readable.push(null)
    return readable
}
const getStream = async (item) => {
    if(Buffer.isBuffer(item)) return { stream: toReadable(item), type: 'buffer' }
    if(item.url.toString().startsWith('http://') || item.url.toString().startsWith('https://')) {
        return { stream: await getGotStream(item.url), type: 'remote' }
    }
    return { stream: createReadStream(item.url), type: 'file' }
}
/** generates a thumbnail for a given media, if required */
async function generateThumbnail(file, mediaType, info) {
    if ('thumbnail' in info) {
        // don't do anything if the thumbnail is already provided, or is null
        if (mediaType === MessageType.audio) {
            throw new Error('audio messages cannot have thumbnails')
        }
    } else if (mediaType === MessageType.image) {
        const buff = await compressImage(file)
        info.thumbnail = buff.toString('base64')
    } else if (mediaType === MessageType.video) {
        const imgFilename = join(tmpdir(), generateMessageID() + '.jpg')
        try {
            await extractVideoThumb(file, imgFilename, '00:00:00', { width: 48, height: 48 })
            const buff = await fs.readFile(imgFilename)
            info.thumbnail = buff.toString('base64')
            await fs.unlink(imgFilename)
        } catch (err) {
            console.log('could not generate video thumb: ' + err)
        }
    }
}
const getGotStream = async(url, options, isStream = true) => {
    const fetched = got.stream(url, { ...options, isStream: true })
    await new Promise((resolve, reject) => {
        fetched.once('error', reject)
        fetched.once('response', ({statusCode: status}) => {
            if (status >= 400) {
                reject(new BaileysError (
                    'Invalid code (' + status + ') returned', 
                    { status }
                ))
            } else {
                resolve(undefined)
            }
        })
    })
    return fetched
} 
const encryptedStream = async(media, mediaType, saveOriginalFileIfRequired = true) => {
    const { stream, type } = await getStream(media)

    const mediaKey = randomBytes(32)
    const {cipherKey, iv, macKey} = getMediaKeys(mediaKey, mediaType)
    // random name
    const encBodyPath = join(tmpdir(), mediaType + generateMessageID() + '.enc')
    const encWriteStream = createWriteStream(encBodyPath)
    let bodyPath
    let writeStream
    if(type === 'file') {
        bodyPath = (media).url
    } else if(saveOriginalFileIfRequired) {
        bodyPath = join(tmpdir(), mediaType + generateMessageID())
        writeStream = createWriteStream(bodyPath)
    }
    
    let fileLength = 0
    const aes = Crypto.createCipheriv('aes-256-cbc', cipherKey, iv)
    let hmac = Crypto.createHmac('sha256', macKey).update(iv)
    let sha256Plain = Crypto.createHash('sha256')
    let sha256Enc = Crypto.createHash('sha256')

    const onChunk = (buff) => {
        sha256Enc = sha256Enc.update(buff)
        hmac = hmac.update(buff)
        encWriteStream.write(buff)
    }
    for await(const data of stream) {
        fileLength += data.length
        sha256Plain = sha256Plain.update(data)
        if (writeStream && !writeStream.write(data)) await once(writeStream, 'drain') 
        onChunk(aes.update(data))
    }
    onChunk(aes.final())

    const mac = hmac.digest().slice(0, 10)
    sha256Enc = sha256Enc.update(mac)
    
    const fileSha256 = sha256Plain.digest()
    const fileEncSha256 = sha256Enc.digest()
    
    encWriteStream.write(mac)
    encWriteStream.end()

    writeStream && writeStream.end()

    return {
        mediaKey,
        encBodyPath,
        bodyPath,
        mac,
        fileEncSha256,
        fileSha256,
        fileLength,
        didSaveToTmpPath: type !== 'file'
    }
}
/**
 * Decode a media message (video, image, document, audio) & return decrypted buffer
 * @param message the media message you want to decode
 */
async function decryptMediaMessageBuffer(message) {
    /* 
        One can infer media type from the key in the message
        it is usually written as [mediaType]Message. Eg. imageMessage, audioMessage etc.
    */
    const type = Object.keys(message)[0]
    if (!type) {
        throw new BaileysError('unknown message type', message)
    }
    if (type === MessageType.text || type === MessageType.extendedText) {
        throw new BaileysError('cannot decode text message', message)
    }
    if (type === MessageType.location || type === MessageType.liveLocation) {
        const buffer = Buffer.from(message[type].jpegThumbnail)
        const readable = new Readable({ read: () => {} })
        readable.push(buffer)
        readable.push(null)
        return readable
    }
    let messageContent
    if (message.productMessage) {
        const product = message.productMessage.product?.productImage
        if (!product) throw new BaileysError ('product has no image', message)
        messageContent = product
    } else {
        messageContent = message[type]
    }
    // download the message
    const fetched = await getGotStream(messageContent.url, {
        headers: { Origin: DEFAULT_ORIGIN }
    })
    let remainingBytes = Buffer.from([])
    const { cipherKey, iv } = getMediaKeys(messageContent.mediaKey, type)
    const aes = Crypto.createDecipheriv("aes-256-cbc", cipherKey, iv)

    const output = new Transform({
        transform(chunk, _, callback) {
            let data = Buffer.concat([remainingBytes, chunk])
            const decryptLength =
                Math.floor(data.length / 16) * 16
            remainingBytes = data.slice(decryptLength)
            data = data.slice(0, decryptLength)

            try {
                this.push(aes.update(data))
                callback()
            } catch(error) {
                callback(error)
            }  
        },
        final(callback) {
            try {
                this.push(aes.final())
                callback()
            } catch(error) {
                callback(error)
            }
        },
    })
    return fetched.pipe(output, { end: true })
}
function extensionForMediaMessage(message) {
    const getExtension = (mimetype) => mimetype.split(';')[0].split('/')[1]
    const type = Object.keys(message)[0]
    let extension
    if (type === MessageType.location || type === MessageType.liveLocation || type === MessageType.product) {
        extension = '.jpeg'
    } else {
        const messageContent = message[type]
        extension = getExtension (messageContent.mimetype)
    }
    return extension
}


module.exports = {Browsers,
toNumber,
waChatKey,
waMessageKey,
WA_MESSAGE_ID,
GET_MESSAGE_ID,
whatsappID,
isGroupID,
newMessagesDB,
shallowChanges,
aesDecrypt,
aesDecryptWithIV,
aesEncrypt,
aesEncrypWithIV,
hmacSign,
sha256,
hkdf,
randomBytes,
unixTimestampSeconds,
debouncedTimeout,
delay,
delayCancellable,
promiseTimeout,
generateMessageTag,
generateClientID,
generateMessageID,
decryptWA,
getMediaKeys,
compressImage,
generateProfilePicture,
ProxyAgent,
mediaMessageSHA256B64,
getAudioDuration,
toReadable,
getStream,
generateThumbnail,
getGotStream,
encryptedStream,
decryptMediaMessageBuffer,
extensionForMediaMessage}