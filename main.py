import hashlib
import json
import configfile
import time
import ecdsa
import base58
import asyncio
import websockets
import codecs
#Coinbase is the blockchain. Infinite spending no auth needed. manageable only by the blockchain.
transaction_template={                                      
      "data" : "hex",                      
      "txid" : "hex",                      
      "hash" : "hex",
      "time":int,
      "coinbase":False
    }

transaction_data_template={
  #"txid":"hex",  this will be added after hashing the hash with sha512
  #"hash":"hex", will be create by hashing all data below as a hex with sha 512
  #"size":int, calculated from hex data together in string
  #"hex":"",
  "version":configfile.Config.version,
  "locktime":int,
  "total_sent":int,
  "out":{
      "value" : int,
      "address":""
  },
  "in":{
    "value":int,
    "scriptPubKey":{
      "address":"",
      "hashedpub":"",
      "scriptSig":{
        "sig":"",
        "pub":""
      },
      "valid":0
    },
    "message":""
  }
}
block_template={
  "version":configfile.Config.version,
  "timeadded":"",
  "previousblockhash":"",
  "mintime":configfile.Config.time_between,
  "total_sent":0,
  "total_transactions":0,
  "transactions":[],
  "height":0,
  "confirmations":0,
  "confirmed":None,
  "confirmed_by":None,
  "nonce":None,
  "hash":""
}


with open(".data/current_block.json") as f:
  current_block=json.load(f)
  if len(current_block.keys())==0:
    current_block=block_template
    with open(".data/current_block.json","w") as f:
      json.dump(current_block,f)
def add_block():
  global current_block
  with open(".data/blockchain.json") as f:
    blockchain=json.load(f)
  current_block['timeadded']=time.time()
  if not blockchain[-1]['confirmations']>=1:
    return {"result":False,"reason":"Last block not confirmed!"}
  current_block['previousblockhash']=blockchain[-1]['hash']
  total_sent=0
  for a in current_block['transactions']:
    data=json.loads(codecs.decode(a['data'],"hex").decode())
    total_sent+=data['total_sent']
  current_block['total_sent']=total_sent
  height=blockchain[-1]['height']+1
  current_block['height']=height
  blockchain.append(current_block)
  with open(".data/blockchian.json","w") as f:
    json.dump(blockchain,f)
  current_block=block_template
  with open(".data/current_block.json","w") as f:
    json.dump(current_block,f)
  
def get_key_balance(key):
  with open(".data/blockchain.json") as f:
    blockchain=json.load(f)
  balance=0
  for a in blockchain:
    for b in a['transactions']:
      data=json.loads(codecs.decode(b['data'],"hex").decode())
      
      if data['in']['scriptPubKey']['address']==key:
        balance+=data['in']['value']
      if data['out']['address']==key:
        balance+=data['out']['value']
  for a in current_block['transactions']:
    data=json.loads(codecs.decode(a['data'],"hex").decode())
    if data['in']['scriptPubKey']['address']==key:
      balance+=data['in']['value']
    if data['out']['address']==key:
      balance+=data['out']['value']
  return balance

def dump_transaction(transaction):
  print("GOOD TrANSACTION")
  current_block['transactions'].append(transaction)
  current_block['total_transactions']=len(current_block['transactions'])
  if len(json.dumps(current_block).encode().hex())>=configfile.Config.max_block_size:
    add_block()
  with open(".data/blockchain.json") as f:
    blockchain=json.load(f)
  if (time.time()-blockchain[-1]['timeadded'])>=configfile.Config.time_between:
    add_block()


def create_transaction(data):
  """DATA TO BE ENTERED
  {
    "scriptSig":{
      "sig":"",
      "pub":""
    },
    "hashed_pub":"",
    "value":int,
    "message":"empty if none",
    "in":"(sender_address)",
    "out":"(receiver_address)"
  }
  
  """
  if len(data['message'])>120:
    return {"result":False,"reason":"Message must be less than 120 characters!"}
  dup_hashed_pubkey=hashlib.new("ripemd160",hashlib.sha512(data["scriptSig"]['pub'].encode()).hexdigest().encode()).hexdigest()
  if not dup_hashed_pubkey==data['hashed_pub']:
    return {"result":False,"reason":"Public key mismatch!"}
  
  sign_msg=(data['scriptSig']['pub']+data['hashed_pub']+str(data['value'])+data['message']+data['in']+data['out']).encode()
  
  verkey= ecdsa.VerifyingKey.from_string(bytearray.fromhex(data['scriptSig']['pub'][2:]), curve=ecdsa.SECP256k1) # the default is sha1
  print(verkey.verify(bytes.fromhex(data['scriptSig']['sig']),sign_msg,hashlib.sha256))

  good=False
  try:
    good=verkey.verify(bytes.fromhex(data['scriptSig']['sig']), sign_msg,hashlib.sha256)
  except:
    return {"result":False,"reason":"Invalid transaction signature!"}
  
  a1=hashlib.sha512(data["scriptSig"]['pub'].encode()).hexdigest()
  a2=hashlib.new("ripemd160",a1.encode()).hexdigest()
  modified_key_hash = "06" + a2
  sha = hashlib.sha512()
  hex_str = modified_key_hash.encode()
  sha.update(hex_str)
  sha_2 = hashlib.sha512()
  sha_2.update(sha.digest())
  checksum = sha_2.hexdigest()[:8]
  byte_address = modified_key_hash + checksum
  address = base58.b58encode(bytes(byte_address.encode())).decode('utf-8')
  if not address==data['in']:
    return {"result":False,"reason":"Public key does not match address!"}
  transaction=transaction_data_template
  if type(data['value'])!=int:
    return {"result":False,"reason":"Invalid value type. Must be int!"}
  transaction['in']['value']=int(data['value']*-1)
  transaction['out']['value']=int(data['value'])
  transaction['out']['address']=data['out']
  transaction['in']['scriptPubKey']['address']=data['in']
  transaction['in']['scriptPubKey']['hashedpub']=data['hashed_pub']
  transaction['in']['scriptPubKey']['valid']=1
  transaction['in']['scriptPubKey']['scriptSig']['sig']=data['scriptSig']['sig']
  transaction['in']['scriptPubKey']['scriptSig']['pub']=data['scriptSig']['pub']
  transaction['in']['message']=data['message']
  transaction['total_sent']=int(data['value'])
  transaction['locktime']=time.time()
  txhex=json.dumps(transaction).encode().hex()
  transaction['hex']=txhex
  transaction['size']=len(transaction['hex'].encode())
  transaction['hash']=hashlib.sha512(txhex.encode()).hexdigest()
  transaction['txid']=hashlib.sha512(transaction['hash'].encode()).hexdigest()
  transaction_temp=transaction_template
  transaction_temp['data']=json.dumps(transaction).encode().hex()
  transaction_temp['txid']=transaction['txid']
  transaction_temp['hash']=transaction['hash']
  transaction_temp['time']=transaction['locktime']
  if not get_key_balance(data['in'])>=data['value']:
    return {"result":False,"reason":"Trying to send more than available!"}
  dump_transaction(transaction_temp)
  return {"result":True,"info":"TXID: "+transaction_temp["txid"]}
  
  
def coinbase_transaction(out,value,message):
  transaction=transaction_data_template
  transaction['in']['scriptPubKey']['address']="Coinbase"
  transaction['in']['scriptPubKey']['scriptSig']['sig']="Coinbase"
  transaction['in']['scriptPubKey']['scriptSig']['pub']="Coinbase"
  transaction['in']['scriptPubKey']['valid']=1
  transaction['out']['address']=out
  transaction['out']['value']=value*configfile.Config.sat
  transaction['in']['message']=message
  transaction['in']['value']=0
  transaction['total_sent']=value
  transaction['locktime']=time.time()
  txhex=json.dumps(transaction).encode().hex()
  transaction['hex']=txhex
  transaction['size']=len(transaction['hex'].encode())
  transaction['hash']=hashlib.sha512(txhex.encode()).hexdigest()
  transaction['txid']=hashlib.sha512(transaction['hash'].encode()).hexdigest()
  transaction_temp=transaction_template
  transaction_temp['data']=json.dumps(transaction).encode().hex()
  transaction_temp['txid']=transaction['txid']
  transaction_temp['hash']=transaction['hash']
  transaction_temp['time']=transaction['locktime']
  transaction_temp['coinbase']=True
  return {"result":True,"info":"Transaction sent, "+transaction_temp['txid']}
def give_miner_job():
  with open(".data/unconfirmed.json") as f:
    unconfirmed=json.load(f)
  if not len(unconfirmed)>0:
    return {"result":False,"reason":"No blocks available to mine at the moment."}
  transactions=codecs.encode(json.dumps(unconfirmed[0]['transactions']).encode(),"hex").decode()
  blob=codecs.encode((str(unconfirmed[0]['height'])+transactions+unconfirmed[0]['previousblockhash']+str(unconfirmed[0]["timeadded"])).encode(),"hex").decode()
  return [blob,str(configfile.Config.difficulty)]

def block_mined(address,nonce,hash):
  with open(".data/blockchain.json") as f:
    blockchain=json.load(f)
  blockchain[-1]['confirmations']+=1
  blockchain[-1]['confirmed']=time.time()
  blockchain[-1]['confirmed_by']=address
  blockchain[-1]['nonce']=nonce
  blockchain[-1]['hash']=hash
  with open('.data/blockchain.json',"w") as f:
    json.dump(blockchain,f)
  coinbase_transaction(address,configfile.Config.block_reward,"Block Reward")
def check_job(data):
  with open(".data/unconfirmed.json") as f:
    unconfirmed=json.load(f)
  transactions=codecs.encode(json.dumps(unconfirmed[0]['transactions']).encode(),"hex").decode()
  blob=codecs.encode((str(unconfirmed[0]['height'])+transactions+unconfirmed[0]['previousblockhash']+str(unconfirmed[0]["timeadded"])).encode(),"hex").decode()
  hashed_blob=hashlib.sha512((blob+str(data[1])).encode()).hexdigest()
  if hashed_blob==data[0] and hashed_blob.startswith("0"*configfile.Config.difficulty):
    block_mined(data[2],data[1],data[0])
    print("GOOD")
    return {"result":True,"info":"Valid"}
  else:
    print("BAD")
    return {"result":False,"reason":"Invalid hash or nonce!"}
  
async def sock(websocket):
    async for message in websocket:
        print(f"[{str(time.time())}]: {message}")
        commands=message.split(";")
        if commands[0]=="GET_JOB":
          await websocket.send("JOB;"+";".join(give_miner_job()))
        elif commands[0]=="BLOCK_FOUND":
          res=check_job([commands[1],commands[2],commands[3]])
          if not res['result']:
            await websocket.send("BAD;"+res['reason'])
          else:
            await websocket.send("GOOD;"+res['info'])
        elif commands[0]=="GET_BALANCE":
          bal=get_key_balance(commands[1])
          await websocket.send("BALANCE;"+str(bal))
        elif commands[0]=="SEND":
          res=create_transaction(json.loads(commands[1]))
          await websocket.send("SEND_RESULT;"+json.dumps(res))
async def main():
    async with websockets.serve(sock, "0.0.0.0", 8000):
        await asyncio.Future()  # run forever
asyncio.run(main())