const http = require('http');
const express = require("express")
const frida  = require("frida")
const nunjucks = require('nunjucks')
const bodyParser = require('body-parser')
const load = require('frida-load')
const socket_io = require('socket.io');
const fs = require("fs");
const moment = require('moment')


const privacy_path = __dirname + "/log/" + "privacy.txt"


const static_path = __dirname + "/views/static"
const template_path = __dirname + "/views/templates"

const app = express()
const server = http.createServer(app);

const io = socket_io(server);
app.set('socket_io', io);
app.use(bodyParser.urlencoded({extended: true}))
app.use(bodyParser.json())
app.use(express.static(static_path))
nunjucks.configure(template_path, {
    autoescape: true,
    watch: true,
    express: app
})

server.listen(10086, () => {
    console.log("Running on http://127.0.0.1:10086/ (Press CTRL+C to quit)")
})

/**
 * 主界面
 * Get请求
 */
app.get("/", async function (req, res) {
    const device = await frida.getUsbDevice()
    const applications = await device.enumerateApplications()
    let template = {
        app_list: applications,
    }
    res.render("device.html", template)
})

let res_start
let target = null
/**
 * 功能界面
 * Post请求
 * 参数有模板界面form表单提供
 */
app.post("/index", async function (req, res) {
    const target_package = req.body.package
    console.log(req.body)
    target = target_package.substring(0, target_package.indexOf("---"))
    type = req.body.type
    if(type == "privacy"){
        try{
            await privacy_init()
        }catch (e) {
            console.log(e)
        }

    }

    res.render("main.html", {})

})

async function privacy_init() {
    const device = await frida.getUsbDevice()
    const pid = await device.spawn(target)
    const session = await device.attach(pid)
    var script_path =  __dirname + "/privacy/script.js"
    console.log(script_path)
    const frida_agent = await load(require.resolve(script_path))
    const script = await session.createScript(frida_agent)
    device.processCrashed.connect(onProcessCrashed)
    session.detached.connect(onSessionDetached)
    script.message.connect(onMessage)
    await script.load()
    api = script.exports
    await device.resume(pid)

}

function io_handler(func, data) {
    io.emit(
        func,
        {
            'data': JSON.stringify(data)
        },
    )
}

function writeFile(data, file_path) {
    if (!data) {
        console.log("data is null")
        return
    }
    console.log(data)
    // const currentTime = moment(Date.now()).format('YYYY-MM-DD HH:mm:ss')
    // const param = currentTime + '\r\n' + data + '\r\n'
    // fs.writeFileSync(file_path, param, {flag: 'a'})
}

function onMessage(message, data) {
    if (!message.payload) {
        console.log("---oops---")
        console.log(message)
        return
    }
    const func = message.payload.function
    const value = message.payload.value
    console.log(value)
    switch (func){
        case "privacy":
            io_handler("webConsole",value)
            break
    }
}
function onProcessCrashed(crash) {
    writeFile('[*] onProcessCrashed() crash:' + JSON.stringify(crash))
}

function onSessionDetached(reason, crash) {
    writeFile('[*] onSessionDetached() reason:' + reason, 'crash:' + JSON.stringify(crash))
}