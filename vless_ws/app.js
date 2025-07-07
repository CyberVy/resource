// vless project on Node.js

// import
import { WebSocketServer } from "ws"
import { connect } from "net"
import crypto from 'crypto'

// const
const password = "HelloWorld."
const uuid_list = [await getUUIDv5FromPassword(password), "af6b9bd6-2993-488c-8c96-a3ea6f7efe05"]

const tg_token = '5866760017:AAFjMuID-LBnn7wX9PJvDxlb_VPYThrWvow'
const tg_id = '5143886367'
const print = console.log

class Waiting extends Promise {

    constructor(executor = (resolve, reject) => { }) {
        let release
        super((resolve, reject) => {
            release = resolve
            executor(resolve, reject)
        })
        this.promise = this
        this.isResolved = false
        this.release = () => {
            release()
            this.isResolved = true
        }
    }
}

class Logger {

    constructor(TGToken, ID, info) {
        this.token = TGToken || tg_token
        this.master_id = ID || tg_id
        this.info = info || ``
    }

    log(text) {
        let message = `${this.info} ` + `${text}`
        print(message)
    }

    async logRemote(text) {
        let message = `${this.info} ` + `${text}`
        print(message)
        try {
            await fetch('https://api.telegram.org/bot' + this.token + '/' + "sendMessage",
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        chat_id: this.master_id,
                        text: message
                    })
                })
        }
        catch (error) {
            print(`logRemote Function error ${error}`)
        }
    }
}

async function getUUIDv5FromPassword(name) {

    async function sha1(array) {

        let myDigest = await crypto.subtle.digest({ name: 'SHA-1', }, array)

        return new array.constructor(myDigest)
    }

    let str = new TextEncoder().encode(name)
    let u = new Uint8Array(16 + str.length)
    u.set(str, 16)
    u = (await sha1(u)).slice(0, -4)

    u[6] = (u[6] & 0x0f) | (5 << 4)
    u[8] = (u[8] & 0x3f) | 0x80

    let to_hex_str = ""
    let item
    for (let i = 0; i < u.length; i++) {
        item = u[i].toString(16)
        if (item.length === 1) { item = "0" + item }
        to_hex_str += item
    }

    let p1 = to_hex_str.slice(0, 8)
    let p2 = to_hex_str.slice(8, 12)
    let p3 = to_hex_str.slice(12, 16)
    let p4 = to_hex_str.slice(16, 20)
    let p5 = to_hex_str.slice(20, 32)

    return p1 + "-" + p2 + "-" + p3 + "-" + p4 + "-" + p5

}

function initializeGlobalVariableViaWebsocketPath(request) {

    function getSearchParam(request, name) {
        let url = new URL("http://0.0.0.0" + request.url)
        let params = new URLSearchParams(url.search)
        return params.get(name)
    }

    let logger = new Logger()
    console.log = getSearchParam(request, "log") ? (...args) => logger.logRemote.apply(logger, args) : (...args) => logger.log.apply(logger, args)

    return { logger }
}

async function parseShadowsocksHeader(data) {

    function ASCII2Str(ascii) {

        let characters = ascii.map(code => String.fromCharCode(code))

        return characters.join('')

    }

    data = new Uint8Array(data)
    let addressType = data[0]
    let headerLen, addressRemote, portRemote, dstAddrLen

    switch (addressType) {
        // domain
        case 3:
            dstAddrLen = data[1]
            addressRemote = data.subarray(2, 2 + dstAddrLen).toString()
            portRemote = data[2 + dstAddrLen] << 8 | data[2 + dstAddrLen + 1]
            headerLen = 4 + dstAddrLen
            addressRemote = ASCII2Str(addressRemote.split(","))
            break
        // ipv4
        case 1:
            addressRemote = data.subarray(1, 5).join('.').toString()
            portRemote = data[5] << 8 | data[6]
            headerLen = 7
            break
        // ipv6
        case 4:
            let addressUint8Array = data.slice(1, 17)
            portRemote = data[17] << 8 | data[18]
            let dataView = new DataView(addressUint8Array.buffer)
            let ipv6 = []
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16))
            }
            addressRemote = ipv6.join(':')
            break
        default:
            return { isUDP: false, rawDataIndex: 0, message: "", hasError: false, addressType: null, headerLen: null, addressRemote: null, portRemote: null }
    }
    return { isUDP: false, rawDataIndex: headerLen, message: "", hasError: false, addressType: addressType, headerLen: headerLen, addressRemote: addressRemote, portRemote: portRemote }
}

async function parseVlessHeader(vlessBuffer, userIDList) {

    vlessBuffer = new Uint8Array(vlessBuffer).buffer
    function Uint8ArrayToUUID(arr, offset = 0) {

        function unsafeStringify(arr, offset = 0) {
            let byteToHex = []
            for (let i = 0; i < 256; ++i) {
                byteToHex.push((i + 256).toString(16).slice(1))
            }
            return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase()
        }

        return unsafeStringify(arr, offset)
    }

    if (vlessBuffer.byteLength < 24) {
        return {
            hasError: true,
            message: 'invalid data',
        }
    }
    let version = new Uint8Array(vlessBuffer.slice(0, 1))
    let isValidUser = false
    let isUDP = false

    if (userIDList.includes(Uint8ArrayToUUID(new Uint8Array(vlessBuffer.slice(1, 17))))) {
        isValidUser = true
    }
    if (!isValidUser) {
        return {
            hasError: true,
            message: 'invalid user',
        }
    }
    let optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0]
    //skip opt for now

    let command = new Uint8Array(
        vlessBuffer.slice(18 + optLength, 18 + optLength + 1)
    )[0]

    // 0x01 TCP
    // 0x02 UDP
    // 0x03 MUX
    if (command === 1) {
    } else if (command === 2) {
        isUDP = true
    } else {
        return {
            hasError: true,
            message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
        }
    }
    let portIndex = 18 + optLength + 1
    let portBuffer = vlessBuffer.slice(portIndex, portIndex + 2)
    // port is big-Endian in raw data etc 80 == 0x005d
    let portRemote = new DataView(portBuffer).getUint16(0)

    let addressIndex = portIndex + 2
    let addressBuffer = new Uint8Array(
        vlessBuffer.slice(addressIndex, addressIndex + 1)
    )

    // 1--> ipv4  addressLength = 4
    // 2--> domain name addressLength=addressBuffer[1]
    // 3--> ipv6  addressLength = 16
    let addressType = addressBuffer[0]
    let addressLength = 0
    let addressValueIndex = addressIndex + 1
    let addressValue = ''
    switch (addressType) {
        case 1:
            addressLength = 4
            addressValue = new Uint8Array(
                vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            ).join('.')
            break
        case 2:
            addressLength = new Uint8Array(
                vlessBuffer.slice(addressValueIndex, addressValueIndex + 1)
            )[0]
            addressValueIndex += 1
            addressValue = new TextDecoder().decode(
                vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            )
            break
        case 3:
            addressLength = 16
            let dataView = new DataView(
                vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            )
            // 2001:0db8:85a3:0000:0000:8a2e:0370:7334
            let ipv6 = []
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16))
            }
            addressValue = ipv6.join(':')
            break
        default:
            console.log(`${addressValue}:${portRemote}`)
            return {
                hasError: true,
                message: `invalid  addressType is ${addressType}`,
            }
    }
    console.log(`${addressValue}:${portRemote}`)
    if (!addressValue) {
        return {
            hasError: true,
            message: `addressValue is empty, addressType is ${addressType}`,
        }
    }
    return {
        hasError: false,
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        vlessVersion: version,
        isUDP,
    }
}

function makeReadableTCPStream(TCPSocket) {

    return new ReadableStream({

        start(controller) {

            TCPSocket.addListener('data', data => {
                controller.enqueue(data)
            })
            TCPSocket.addListener('end', () => {
                    controller.close()
                    console.log('TCP Disconnected from server.')
                }
            )
            TCPSocket.addListener('error', (error) => {
                    controller.close()
                    console.log(error.message)
                }
            )
        },
        cancel(reason) {
            TCPSocket.end()
            console.log(`Stream is canceled, due to ${reason}`)
        }
    })
}

function makeReadableWebSocketStream(websocket, secWebsocketProtocol) {

    function base64StrToUint8Array(base64Str) {

        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/')
        return Uint8Array.from(atob(base64Str), (c) => c.charCodeAt(0)).buffer
    }

    let secWebsocketProtocolArray
    return new ReadableStream({
        start(controller) {
            websocket.addEventListener('message', event => {
                controller.enqueue(event.data)
            })
            websocket.addEventListener('close', () => {
                controller.close()
                console.log("Websocket is closed.")
            })
            websocket.addEventListener('error', (error) => {
                controller.close()
                console.log(`Websocket error: ${error.message}`)
            })
            if (secWebsocketProtocol) {
                try {
                    secWebsocketProtocolArray = base64StrToUint8Array(secWebsocketProtocol)
                    controller.enqueue(secWebsocketProtocolArray)
                }
                catch (secWebsocketProtocolArrayTransformingError) {
                    controller.error(secWebsocketProtocolArrayTransformingError)
                }
            }
        },
        cancel(reason) {
            console.log(`Stream is cancelled due to ${reason}`)
        }
    })
}

function writeReadableStream(readableStream, writeFunction, closeFunction, abortFunction) {

    let counter = 0
    return readableStream.pipeTo(new WritableStream({

        async write(chunk, controller) {
            await writeFunction(chunk, counter, controller)
            counter++
        },
        close() {
            closeFunction ? closeFunction() : console.log(`Stream is closed.`)
        },
        abort(reason) {
            abortFunction ? abortFunction() : console.log(`Stream is aborted due to ${reason}`)
        }
    }))
}

async function Shadowsocks(port= 2052) {

    let webSocketServer = new WebSocketServer({ host: "::", port: port })

    webSocketServer.on("connection", async (clientSocket, request) => {

        let { logger } = initializeGlobalVariableViaWebsocketPath(request)

        let earlyDataHeader = request.headers['sec-websocket-protocol'] || ''
        let readableWebSocketStream = makeReadableWebSocketStream(clientSocket, earlyDataHeader)
        let TCPSocket
        let TCPSocketWriter
        let waitForTCPSocket = new Waiting()
        writeReadableStream(readableWebSocketStream, async (chunk, counter) => {
            if (!counter) {
                let {
                    hasError, message, portRemote, addressRemote,
                    rawDataIndex, isUDP,
                } = await parseShadowsocksHeader(chunk)
                let rawClientData = chunk.slice(rawDataIndex)

                logger.info = `[SHADOWSOCKS] ${request.connection.remoteAddress}\n${addressRemote}:${portRemote}`
                TCPSocket = connect({ host: addressRemote, port: portRemote })
                let i = 0
                TCPSocket.addListener('end', () => {
                    i++
                    clientSocket.close()
                    if (i === 1){
                        console.log("Connection closed by TCPSocket.")
                    }
                })
                clientSocket.addEventListener("close",() => {
                    i--
                    TCPSocket.end()
                    if (i === -1){
                        console.log("Connection closed by Websocket.")
                    }
                })
                waitForTCPSocket.release()
                TCPSocketWriter = TCPSocket
                if (rawClientData.byteLength !== 0) {
                    try {
                        TCPSocketWriter.write(rawClientData)
                    }
                    catch (error) {
                        console.log("(TLS Hello Failed.) Connection with remote server has lost.")
                    }
                }
            }
            else {
                TCPSocketWriter = TCPSocket
                try {
                    TCPSocketWriter.write(chunk)
                }
                catch (error) {
                    console.log("Connection with remote server has lost.")
                }
            }
        }, () => clientSocket.close(), () => clientSocket.close()).catch(error => console.log(`Forward Abort.`))
        await waitForTCPSocket
        writeReadableStream(makeReadableTCPStream(TCPSocket), async (chunk, counter) => {
            clientSocket.send(chunk)
        }, () => clientSocket.close(), () => clientSocket.close()).catch(error => console.log(`Backward Abort.`))
        clientSocket.addEventListener("error", console.log)
    })
}

async function Vless(port = 80) {

    let webSocketServer = new WebSocketServer({ host: "::", port: port })

    webSocketServer.on("connection", async (clientSocket, request) => {

        let { logger } = initializeGlobalVariableViaWebsocketPath(request)

        let earlyDataHeader = request.headers['sec-websocket-protocol'] || ''
        let readableWebSocketStream = makeReadableWebSocketStream(clientSocket, earlyDataHeader)
        let TCPSocket
        let TCPSocketWriter
        let responseHeader
        let waitForTCPSocket = new Waiting()
        writeReadableStream(readableWebSocketStream, async (chunk, counter) => {
            if (!counter) {
                let {
                    hasError, message, portRemote, addressRemote,
                    rawDataIndex, vlessVersion = new Uint8Array([0, 0]), isUDP,
                } = await parseVlessHeader(chunk, uuid_list)
                let rawClientData = chunk.slice(rawDataIndex)
                responseHeader = new Uint8Array([vlessVersion[0], 0])

                logger.info = `[VLESS] ${request.connection.remoteAddress}\n${addressRemote}:${portRemote}`
                TCPSocket = connect({ host: addressRemote, port: portRemote })
                let i = 0
                TCPSocket.addListener('end', () => {
                    i++
                    clientSocket.close()
                    if (i === 1){
                        console.log("Connection closed by TCPSocket.")
                    }
                })
                clientSocket.addEventListener("close",() => {
                    i--
                    TCPSocket.end()
                    if (i === -1){
                        console.log("Connection closed by Websocket.")
                    }
                })
                waitForTCPSocket.release()
                TCPSocketWriter = TCPSocket
                if (rawClientData.byteLength !== 0) {
                    try {
                        TCPSocketWriter.write(rawClientData)
                    }
                    catch (error) {
                        console.log("(TLS Hello Failed.) Connection with remote server has lost.")
                    }
                }
            }
            else {
                TCPSocketWriter = TCPSocket
                try {
                    TCPSocketWriter.write(chunk)
                }
                catch (error) {
                    console.log("Connection with remote server has lost.")
                }
            }
        }, () => clientSocket.close(), () => clientSocket.close()).catch(error => console.log(`Forward Abort.`))
        await waitForTCPSocket
        writeReadableStream(makeReadableTCPStream(TCPSocket), async (chunk, counter) => {
            if (!counter) {
                clientSocket.send(await new Blob([responseHeader, chunk]).arrayBuffer())
            }
            else {
                clientSocket.send(chunk)
            }
        }, () => clientSocket.close(), () => clientSocket.close()).catch(error => console.log(`Backward Abort.`))
        clientSocket.addEventListener("error", console.log)
    })
}

Vless(80)
Shadowsocks(2052)
