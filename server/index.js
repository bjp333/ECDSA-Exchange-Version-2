const express = require('express');
const app = express();
const cors = require('cors');
const port = 3042;
const SHA256 = require('crypto-js/sha256');
const secp = require("@noble/secp256k1");


app.use(cors());
app.use(express.json());



const hex = secp.utils.bytesToHex;

let privateKey1 = hex(secp.utils.randomPrivateKey());
let privateKey2 = hex(secp.utils.randomPrivateKey());
let privateKey3 = hex(secp.utils.randomPrivateKey());

//privateKey1 = Buffer.from(privateKey1).toString();  
//privateKey2 = Buffer.from(privateKey2).toString();  
//privateKey3 = Buffer.from(privateKey3).toString();  

let publicKey1 = hex(secp.getPublicKey(privateKey1));
let publicKey2 = hex(secp.getPublicKey(privateKey2));
let publicKey3 = hex(secp.getPublicKey(privateKey3));

publicKey1 = "0x" + publicKey1.slice(publicKey1.length-40);
publicKey2 = "0x" + publicKey2.slice(publicKey2.length-40);
publicKey3 = "0x" + publicKey3.slice(publicKey3.length-40);


const balances = {
  [publicKey1]: 100,
  [publicKey2]: 50,
  [publicKey3]: 75
}


/*
  app.get() function lets you define a route handler for GET requests to a given URL
  First parameter to app.get () is called a path.  The path string supports
  several special characters that let you use a subset or regular expressions in path strings

  Route parameters are essentially variables defined from named sections of the URL.  Express
  parses the URL, pulls the value in the anmed section, and stores it in the req.params
  property
*/
app.get('/balance/:address', (req, res) => {
  const {address} = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post('/send', (req, res) => {
//  const {sender, recipient, amount} = req.body;
//  balances[sender] -= amount;
//  balances[recipient] = (balances[recipient] || 0) + +amount;
//  res.send({ balance: balances[sender] });

/*
  app.post() function routes the HTTP POST requests to the specified path
  with the specified callback functions.
*/
    const {recipient, amount, signature, recovery} = req.body;
    // req.body = req is the request object
    
    const message = JSON.stringify({
      to: recipient,
      amount: parseInt(amount)
    });

    const messageHash = SHA256(message).toString();

    // recover the public key using msgHash, sig, and recoveryBit
    const recoveredPublicKey = hex(secp.recoverPublicKey(messageHash, signature, parseInt(recovery)));

    // clean up recovered public key so that we can look up if it matches our own server records
    const senderPublicKey = "0x" + recoveredPublicKey.slice(recoveredPublicKey.length - 40);

    let publicKeyMatch = true;

   if(!balances[senderPublicKey]) {

      console.error("Public key does not match.  Make sure you're using correct values!");
      publicKeyMatch = false;
    }

    console.log(senderPublicKey + " is attempting to send " + amount + " to " + recipient);

    // verify signature using independent message hash, sig, recoveredPublicKey
    const isSigned = secp.verify(signature, messageHash, recoveredPublicKey);

    //only if isSigned passes, allow transfer of funds
    // this means whoever sent the signature, owns the private key associated to the funds

    if(isSigned && publicKeyMatch) {
      balances[senderPublicKey] -= amount;
      balances[recipient] = (balances[recipient] || 0) + +amount;
      res.send({ balance: balances[senderPublicKey]});
      console.log(senderPublicKey + " has successfully sent " + amount + " to "+ recipient);
      logBalances();
    } else {
      console.error("something seems off!  Make sure you are passing in the correct values!");
      logBalances();
    }
  });

function logBalances() {
  console.log("Available Accounts");
  console.log("==========================================");
  console.log();
  console.log("(0) " + publicKey1 + "(" + balances[publicKey1]+")");
  console.log("(1) " + publicKey2 + "(" + balances[publicKey2]+")");
  console.log("(2) " + publicKey3 + "(" + balances[publicKey3]+")");
  console.log();
  console.log("Private Keys");
  console.log("==========================================");
  console.log("(0) " + privateKey1);
  console.log("(1) " + privateKey2);
  console.log("(2) " + privateKey3);
}

app.listen(port, () => {
  console.log();
  console.log(`Listening on port ${port}!`);
  logBalances();
});
