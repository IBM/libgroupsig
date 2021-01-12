// /mocks/behaviors.js

const { Behavior } = require("@mocks-server/main");

const { verifyCert } = require("./fixtures/pki");

const standard = new Behavior([
  verifyCert,
  "verify-cert"
], {
  id: "standard"
});

const dynamic = standard.extend([ verifyCert ], {
  id: "dynamic"
});

module.exports = [ standard, dynamic ];
