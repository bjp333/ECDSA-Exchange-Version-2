const secp = require("@noble/secp256k1");
const SHA256 = require('crypto-js/sha256');
const hex = secp.utils.bytesToHex;
(async () => {
  // copy-paste a private key generated when running server/index.js
  const privateKey = "0cd047eaeaa8c745e186639a4ef7d70759595a710d02453fa8b12e3f42d2b468";

  // copy-paste a separate account from your server db in to
  // send an amount less than your current balance!
  const message = JSON.stringify({
    to: "0xc8f71f3448b3131c31c5094bf456cab0d92b9599",
    amount: 5
  });

  // hash your message
  const messageHash = SHA256(message).toString();

  // use secp.sign() to produce signature and recovery bit (response is an array of two elements)
  const signatureArray = await secp.sign(messageHash, privateKey, {
    recovered: true
  });
  // separate out returned array into the string signature and the number recoveryBit
  const signature = hex(signatureArray[0]);
  const recoveryBit = signatureArray[1];

  // use these values in your client!
  console.log("Signature: " + signature);
  console.log("Recovery bit: " + recoveryBit);
})();