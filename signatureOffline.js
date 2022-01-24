const secp = require("@noble/secp256k1");
const SHA256 = require('crypto-js/sha256');
const hex = secp.utils.bytesToHex;
(async () => {
  // copy-paste a private key generated when running server/index.js
  const privateKey = "f9cbe3013f5ad8d43f1695a006e1eed9706eea280a7adce767fe5f98f1dc5bfb";

  // copy-paste a separate account from your server db in to
  // send an amount less than your current balance!
  const message = JSON.stringify({
    to: "0xbfd27466b3ba875294733dd180e73cb05bb288b4",
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