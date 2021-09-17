<template>
  <v-container class="mt-2">
    
    <span class="hd1">Avalanche Wallet Signature Verification Demo</span>
    <div class="head">
    <span class="hd2"> using a Smart Contract, by </span> 
    <img class="logo" src="../assets/rediyeti.png">
    </div>
    <v-form ref="form" v-model="valid">
      <h3 class="mb-5">Inputs</h3>
      <v-row>
        <v-col cols="12" sm="6" md="6">
          <label>Fuji Testnet X-Chain Address</label>
          <v-text-field v-model="xchain" :rules="[v => !!v || 'X-chain address is required']" outlined required class="mt-3"></v-text-field>
        </v-col>
        <v-col cols="12" sm="6" md="6">
          <label>Message</label>
          <v-text-field v-model="msg" :rules="[v => !!v || 'Message is required']" outlined required class="mt-3"></v-text-field>
        </v-col> 
      </v-row>
      <label>Signature</label>
      <v-text-field name="sign" v-model="sig" :rules="[v => !!v || 'Signature is required']" outlined required class="mt-3"></v-text-field>
      <v-btn color="#E63940" class="mr-4 white--text" @click="metamaskStatus">Verify</v-btn>
      <v-btn color="#E63940" class="mr-4 white--text" @click="reset">Reset</v-btn>
      <h3 class="mb-5 mt-10">Output</h3>
      <label>Result</label>
      <v-text-field name="sign" v-model="result" outlined class="mt-3"></v-text-field>
    </v-form>
  </v-container>
</template>

<style scoped>
.logo {
  height: 60px;
}
.head {
  display: flex;
  align-items: center;
  /* justify-content: center; */
  margin-bottom: 30px;
  margin-top: -6px;
}
.hd1 {
  font-size: 32px;
  font-weight: bold;
  margin-top: 6.5px;
  /* margin-right: 11px; */
}
.hd2 {
  font-size: 32px;
  font-weight: bold;
  /* margin-bottom: -5px; */
  margin-right: 11px;
}
</style>

<script lang="ts">
const ECArtifact = require("../contracts/EC.json")
const contractAddress = require("../contracts/contract-address.json")
import { ethers } from 'ethers';
import { ec as EC } from 'elliptic';
import { BinTools, Buffer } from 'avalanche'
import createHash from 'create-hash'
import BN from 'bn.js';

export default {
  name: "Verify",

  data() {
    return {
      valid: true,
      xchain: '',
      msg: '',
      sig: '',
      result: ''
    }
  },
    
  methods: {

    // Check if Metamask is installed, if installed then check if it is connected to Avalanche Fuji Testnet
    metamaskStatus() {
      if((window as any).ethereum) {
        if((window as any).ethereum.chainId != '0xa869') {
          this.result = "Failed: Not connected to Avalanche Fuji Testnet via Metamask."
        }
        else{
          this.verify()
        }
      }
      else {
        this.result = "Failed: Metamask is not installed."
      }
    },

    //Check X-chain address is a Fuji X-chain address
    checkXc(){
      if(!(this.xchain.startsWith("X-fuji1"))) {
        return false
      }
      else{
        return true
      }
    },

    //Get the message hash with magic prefix
    hashMessage() {
        let mBuf: Buffer = Buffer.from(this.msg, 'utf8')       //creates buffer with the message
        let msgSize: Buffer = Buffer.alloc(4)                 //creates a 4 bytes buffer object
        msgSize.writeUInt32BE(mBuf.length, 0)         //write a number to an instance of the Buffer class
        let msgBuf: Buffer = Buffer.from(`\x1AAvalanche Signed Message:\n${msgSize}${this.msg}`, 'utf8')   //creates message buffer with the magic prefix, message length and message
        let hash: Buffer = createHash('sha256').update(msgBuf).digest()   //hashes the message buffer with sha256
        let hashex: string = hash.toString('hex')       //coverts buffer to hex
        let hashBuff: Buffer = Buffer.from(hashex, 'hex')
        let messageHash: string = '0x' + hashex
        return {hashBuff, messageHash}
    },
    
    //Split the signature into r,s and v parameters
    splitSig() {
      try{
        let bintools: BinTools = BinTools.getInstance()
        let decodedSig: Buffer = bintools.cb58Decode(this.sig)      //Decode the signature as Avalanche Wallet produces cb58 encoded signature
        const r: BN = new BN(bintools.copyFrom(decodedSig, 0, 32))     //split first 32 bytes to r
        const s: BN = new BN(bintools.copyFrom(decodedSig, 32, 64))    //split next 32 bytes to s
        const v: number = bintools.copyFrom(decodedSig, 64, 65).readUIntBE(0, 1)     //split last 1 byte to v
        const sigParam: any = {
          r: r,
          s: s,
          v: v
        }
        let rhex: string = '0x' + r.toString('hex')     //converts r to hex
        let shex: string = '0x' + s.toString('hex')   //converts s to hex
        let sigHex: Array<string> = [rhex, shex]
        return {sigParam, sigHex}
      }
      catch{
        this.result = "Failed: Invalid signature."
      }
    },

    //Recover public key
    recover(msg: Buffer, sig: any) {
      let ec: EC = new EC('secp256k1')
      const pubk: any = ec.recoverPubKey(msg, sig, sig.v)
      const pubkx: string = '0x' + pubk.x.toString('hex')     //public key x coordinate
      const pubky: string = '0x' + pubk.y.toString('hex')     //public key y coordinate
      let pubkCord: Array<string> = [pubkx, pubky]
      let pubkBuff: Buffer = Buffer.from(pubk.encodeCompressed())
      return {pubkCord, pubkBuff}
    },

    // Verify the signature and get the signer address from Dapp
    async verify() {
      const provider: any = new ethers.providers.Web3Provider((window as any).ethereum)
      const elliptic: any = new ethers.Contract(contractAddress.Contract, ECArtifact.abi, provider)
      if(this.xc == '' || this.msg == '' || this.sig == '') {
        this.result = "Signature Verification Failed"
      }
      else {
        let xc = this.checkXc()
        if (xc) {
          let message: any = this.hashMessage()
          let sign: any = this.splitSig()
          let publicKey: any = this.recover(message.hashBuff, sign.sigParam)
          let prefix: string = "fuji"
          let hrp: Array<any> = []    //array of unicode of prefix
          for (var i=0; i<prefix.length; i++) {
            hrp[i] = prefix.charCodeAt(i)
          }
          const tx: string = await elliptic.recoverAddress(message.messageHash, sign.sigHex, publicKey.pubkCord, publicKey.pubkBuff, this.xchain, prefix, hrp)
          this.result = tx
        }
        else{
          this.result = "Halted: X-Chain address must be for the Avalanche Fuji Testnet."
        }
      }
    },

    //Reset form
    reset() {
      this.$refs.form.reset()
      this.result = ''
    }
  }
};
</script>
