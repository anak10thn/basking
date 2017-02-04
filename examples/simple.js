var http = require('../');
var assert = require('assert');

var req = "GET / HTTP/1.1\r";
    req += "Host: blooperblorp\r";
    req += "Cookie: blah=woop\r";

var env = {};
// assert.equal('/blakjsdfkas', env.PATH_INFO);
// assert.equal('', env.QUERY_STRING);
// assert.equal('GET', env.REQUEST_METHOD);
// assert.equal('/blakjsdfkas', env.REQUEST_URI);
// assert.equal('', env.SCRIPT_NAME);
// assert.equal('HTTP/1.1', env.SERVER_PROTOCOL);
console.log(http.parser(req,env));
