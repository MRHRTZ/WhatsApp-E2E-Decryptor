const QR = require('qrcode-terminal')
const Curve = require('curve25519-js')
const Utils = require('./src/Decfile/Utils')
const express = require('express')
const app = express()
const PORT = process.env.PORT || 2015
const util = require('util')
const fs = require('fs')
const {
    WebSocketServer
} = require('ws');
const Decoder = require('./src/Binary/Decoder')



let json = {
    ['clientID']: {
        key: {
            curveKeys: '',
            publicKey: '',
            secret: ''
        },
        user: {
            // jid: Utils.whatsappID(json.wid),
            name: '', //json.pushname,
            phone: '', //json.phone,
            imgUrl: null
        },
        authInfo: {
            encKey: '',
            macKey: '',
            clientToken: '',
            serverToken: '',
            browserToken: '',
            clientID: '',
        }
    }
}

if (fs.existsSync('./sessions.json')) {
    try {
        const jsn = JSON.parse(fs.readFileSync('./sessions.json'))
        json[jsn.clientID] = jsn
        console.log(json)
        json[jsn.clientID].encKey = Buffer.from(json[jsn.clientID].encKey, 'base64')
        json[jsn.clientID].macKey = Buffer.from(json[jsn.clientID].macKey, 'base64')
    } catch (e) {
        console.log(e);
    }
}

function initAuth(json, clientID) {
    const secret = Buffer.from(json[clientID].key.secret, 'base64')
    if (secret.length !== 144) {
        throw new Error('incorrect secret length received: ' + secret.length)
    }

    // generate shared key from our private key & the secret shared by the server
    const sharedKey = Curve.sharedKey(json[clientID].key.curveKeys.private, secret.slice(0, 32))
    // expand the key to 80 bytes using HKDF
    const expandedKey = Utils.hkdf(sharedKey, 80)

    const hmacValidationKey = expandedKey.slice(32, 64)
    const hmacValidationMessage = Buffer.concat([secret.slice(0, 32), secret.slice(64, secret.length)])

    const hmac = Utils.hmacSign(hmacValidationMessage, hmacValidationKey)

    if (!hmac.equals(secret.slice(32, 64))) {
        // if the checksums didn't match
        throw new Error('HMAC validation failed', json)
    }
    const encryptedAESKeys = Buffer.concat([
        expandedKey.slice(64, expandedKey.length),
        secret.slice(64, secret.length),
    ])
    const decryptedKeys = Utils.aesDecrypt(encryptedAESKeys, expandedKey.slice(0, 32))
    // set the credentials
    let authInfo = {
        encKey: decryptedKeys.slice(0, 32).toString('base64'), // first 32 bytes form the key to encrypt/decrypt messages
        macKey: decryptedKeys.slice(32, 64).toString('base64'), // last 32 bytes from the key to sign messages
        clientToken: json[clientID].clientToken,
        serverToken: json[clientID].serverToken,
        clientID: json[clientID].clientID,
    }
    json[clientID] = authInfo
    return authInfo
}

function respondToChallenge(challenge, macKeybs64, serverToken, clientID) {
    const bytes = Buffer.from(challenge, 'base64') // decode the base64 encoded challenge string
    const signed = Utils.hmacSign(bytes, Buffer.from(macKeybs64, 'base64')).toString('base64') // sign the challenge string with our macKey
    const rawjson = ['admin', 'challenge', signed, serverToken, clientID] // prepare to send this signed string with the serverToken & clientID

    console.log('resolving login challenge')
    return `${Math.floor(new Date().valueOf() / 1000)},["${rawjson.join('","')}"]`
}

function generateKeysForAuth(ref, cid) {
    json[cid].key.curveKeys = Curve.generateKeyPair(Utils.randomBytes(32))
    json[cid].key.publicKey = Buffer.from(json[cid].key.curveKeys.public).toString('base64')
    json[cid].clientID = cid
    const qr = [ref, json[cid].key.publicKey, json[cid].clientID].join(',')
    // const genr = QR.generate(qr, { small: true })
    // console.log(genr)
    return {
        clientID: json[cid].clientID,
        curveKeys: json[cid].key.curveKeys,
        publicKey: json[cid].key.publicKey,
        qr
    }
}

function initLogin(cid) {
    json[cid] = {
        key: {}
    }
    return `${Math.floor(new Date().valueOf() / 1000)},["admin","init",[2,2140,12],["HZ Testing","Safari","x86_64"],"${cid}",true]`
}

app.get('/login', (req, res) => {
    // res.setHeader('Content-Type', 'application/json')
    console.log('log in')
    res.send(initLogin(Utils.generateClientID()))
})

app.get('/restore1/:clientID', (req, res) => {
    // res.setHeader('Content-Type', 'application/json')
    console.log('restore 1')
    if (json[clientID].encKey) {
        let init = initLogin(req.params.clientID)
        res.send(init)
    } else {
        console.log('You must sign first!')
        res.send('You must sign first!')
    }
})

app.get('/restore2/:clientToken/:serverToken/:clientID', (req, res) => {
    // res.setHeader('Content-Type', 'application/json')
    console.log('restore 2')
    if (json.authInfo.encKey) {
        let str = `${Math.floor(new Date().valueOf() / 1000)},["admin","login","${req.params.clientToken}","${req.params.serverToken}","${req.params.clientID}","takeover"]`
        res.send(str)
    } else {
        console.log('You must sign first!')
        res.send('You must sign first!')
    }
})

app.get('/challenge/:challenge/:macKeybs64/:serverToken/:clientID', (req, res) => {
    // res.setHeader('Content-Type', 'application/json')
    console.log('challenge')
    const {
        challenge,
        macKeybs64,
        serverToken,
        clientID
    } = req.params
    res.send(respondToChallenge(challenge, macKeybs64, serverToken, clientID))
})

app.get('/getqr/:ref/:cid', (req, res) => {
    // res.setHeader('Content-Type', 'application/json')
    console.log('getqr')
    const {
        ref,
        cid
    } = req.params
    res.send(generateKeysForAuth(ref, cid))
})

app.get('/inputsecret/:secret/:clientID', (req, res) => {
    // res.setHeader('Content-Type', 'application/json')
    // const { ref, cid } = req.params
    console.log('secret input')

    json[req.params.clientID].key.secret = req.params.secret
    res.sendStatus(200)
})

app.get('/initAuth/:clientID', (req, res) => {
    console.log('Decrypt and get enckey & mackey')
    // res.setHeader('Content-Type', 'application/json')
    // const { ref, cid } = req.params
    res.send(JSON.stringify(initAuth(json, req.params.clientID), null, 4))
})

app.get('/getAll', (req, res) => {
    // res.setHeader('Content-Type', 'application/json')
    res.send(JSON.stringify(json, null, 3))
})

app.get('/', (req, res) => {
    // res.setHeader('Content-Type', 'application/json')
    res.sendStatus(200)
})

// app.get('/eval/:code', (req, res) => {
//     // res.setHeader('Content-Type', 'application/json')
//     const {
//         code
//     } = req.params.code
//     try {
//         res.send(util.format(eval(code)))
//     } catch (error) {
//         res.send(util.format(error))
//     }
// })

const wss = new WebSocketServer({
    port: 2014
});

allWs = []
setInterval(() => {
    console.log('Sending ping')
    allWs.forEach(ws => {
        ws.send('{"action":"ping","status":200,"value":"?,,"}')
    });
}, 20000); //20 sec

wss.on('connection', function connection(ws) {
    allWs.push(ws)
    ws.on('message', function incoming(message) {
        console.log('received: %s', message.slice(0, 100));
        try {
            let data = JSON.parse(message)
            // { cmd: '', clientID: '', macKey: '' }
            if (data.cmd == 'login') {
                ws.send(JSON.stringify({
                    action: 'login',
                    status: 200,
                    value: initLogin(Utils.generateClientID())
                }))
            } else if (data.cmd == 'restore1') {
                if (data.clientID) {
                    let init = initLogin(data.clientID)
                    ws.send(JSON.stringify({
                        action: 'restore1',
                        status: 200,
                        value: init
                    }))
                } else {
                    console.log('You must sign first!')
                    ws.send(JSON.stringify({
                        action: 'restore1',
                        status: 403,
                        message: 'You must sign first!'
                    }))
                }
            } else if (data.cmd == 'restore2') {
                if (data.encKey && data.clientToken && data.serverToken && data.clientID) {
                    let str = `${Math.floor(new Date().valueOf() / 1000)},["admin","login","${data.clientToken}","${data.serverToken}","${data.clientID}","takeover"]`
                    ws.send(JSON.stringify({
                        action: 'restore2',
                        status: 200,
                        value: str
                    }))
                } else {
                    console.log('You must sign first!')
                    ws.send(JSON.stringify({
                        action: 'restore2',
                        status: 403,
                        message: 'You must sign first!'
                    }))
                }
            } else if (data.cmd == 'challenge') {
                if (data.challenge && data.macKeybs64 && data.serverToken && data.clientID) {
                    const {
                        challenge,
                        macKeybs64,
                        serverToken,
                        clientID
                    } = data
                    let rest = respondToChallenge(challenge, macKeybs64, serverToken, clientID)
                    ws.send(JSON.stringify({
                        action: 'challenge',
                        status: 200,
                        value: rest
                    }))

                } else {
                    ws.send(JSON.stringify({
                        action: 'challenge',
                        status: 401,
                        message: 'Missing parameter'
                    }))
                }
            } else if (data.cmd == 'getqr') {
                if (data.ref && data.clientID) {
                    const keys = generateKeysForAuth(data.ref, data.clientID)
                    ws.send(JSON.stringify({
                        action: 'getqr',
                        status: 200,
                        value: keys
                    }))
                } else {
                    ws.send(JSON.stringify({
                        action: 'getqr',
                        status: 401,
                        message: 'Missing parameter'
                    }))

                }
            } else if (data.cmd == 'inputsecret') {
                if (data.secret && data.clientID) {
                    json[data.clientID].key.secret = data.secret
                    ws.send(JSON.stringify({
                        action: 'inputsecret',
                        status: 200
                    }))
                } else {
                    ws.send(JSON.stringify({
                        action: 'inputsecret',
                        status: 401,
                        message: 'Missing parameter'
                    }))
                }
            } else if (data.cmd == 'initAuth') {
                if (data.clientID) {
                    let init = initAuth(json, data.clientID)
                    ws.send(JSON.stringify({
                        action: 'initAuth',
                        status: 200,
                        value: init
                    }))
                } else {
                    ws.send(JSON.stringify({
                        action: 'initAuth',
                        status: 401,
                        message: 'Missing parameter'
                    }))
                }
            } else if (data.cmd == 'decryptMessage') {
                if (data.macKey && data.encKey && data.binaryMessage) {
                    try {
                        let message = Buffer.from(data.binaryMessage, 'base64')
                        let macBuff = Buffer.from(data.macKey, 'base64')
                        let encBuff = Buffer.from(data.encKey, 'base64')
                        let decrypt = Utils.decryptWA(message, macBuff, encBuff, new Decoder())
                        ws.send(JSON.stringify({
                            action: 'decryptMessage',
                            status: 200,
                            value: decrypt
                        }))
                    } catch (e) {
                        console.log(e)
                    }
                } else {
                    ws.send(JSON.stringify({
                        action: 'decryptMessage',
                        status: 401,
                        message: 'Missing parameter'
                    }))
                }
            }
        } catch (e) {
            console.log('Error : %s', e);
        }
    });

    ws.send('{"action":"open","status":200}');
});

app.listen(PORT, () => {
    console.log('Server run at PORT :', PORT)
})