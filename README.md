# aepp-token-migration-backend

## Token Migration Overview
Around 2nd of September 2019, all ERC 20 Aeternity tokens will be frozen. All ethereum holders need to be able to migrate their tokens to the mainnet after the Lima hardfork. We will provide an easy to use solution to help the community to migrate safely their tokens to the new network.

This solution will consist of several parts - migrator web-app, migration back-end app, and aeternity smart contract. The general idea is to allow the ethereum users to sign a message (their aeternity address) with their private key and send it to an Aeternity smart contract. The Aeternity smart contract will recover the ethereum address of the signer and check whether this is a user that has a balance on the ethereum mainnet. If this is proven to be an ethereum AE holder, the smart contract will disburse the exact number of AE to the users AE address in the Aeternity network.

Obviously, an aeternity smart contract cannot reach to the ethereum network. In order for the smart contract to check the balance, a list of all ethereum AE holder balances needs to be available. The sheer number of ethereum AE holders (20000+) makes the storing of such a list in the smart contract unfeasible. To solve this problem we will introduce Merkle tree-based solution.

A backend app is going to create and maintain a Merkle tree of all ethereum AE holders and their balances. The merkle tree root hash will be stored in the Aeternity smart contract and through the use of hashing (and some additional data - index and intermediary hashes), the Aeternity smart contract will be able to check the validity of the migration claim by a given user. This back-end app will be open-source and can be run by everyone in multiple instances to ensure decentralization.

## Workflow
To begin the migration the users must provide their aeternity accounts. If they lack one, ability to create will be present. After that, the users must authenticate with their Etherum address. There are two ways of achieving that - with Metamask or MyEtherWallet. The first phase will support only Metamask. After the authentication, the balance that will be migrated will be shown and they will be prompt to sign a message with their ethereum private key. The message must be their aeternity account! Once the message is signed, the client-side will build a transaction for the token migration. The raw transaction will be sent to the backend. On the other hand, the backend will have the ability to sign and send the transaction. The backend will have several functions, create and store the merkle tree information, send the necessary information to the client-side and send the transactions. The merkle tree approach was chosen because it is far more cheap to use than storing all ethereum addresses and balances into a smart contract. From all addresses and balance, the backend will create the merkle tree and store the hashes into a Postgre database. The smart contract will serve as a proof and migrate the tokens.

## Backend
The backend will be used to join needed data(amount of tokens, merkle tree leaf index and an array of intermediary hashes) from provided user ethereum address, AE address and signature(signed AE address). With this data, backend would create contract call tx, sign it with internal wallet and broadcast it. If smart contract accepts(verifies) current request would transfer tokens to provided AE address, emit event and would return number of transfer. After that backend would notify backendless service for current transfer and user would not be able to transfer it again.

### Installation
What you should have installed 
 - Go: https://golang.org/dl/
 - local postgresql(https://www.postgresql.org/download/) or connect to remote one

clone this repo into `$GOPATH/go/src`
in project root directory `go get`
// windows users: if you get this error: '"gcc": executable file not found in %PATH%'
// download and install: 'TDM-GCC' is a compiler suite for Windows. http://tdm-gcc.tdragon.net/download
// then repeat command `go get` or `go get -u`


set the environment variables in an .env file. You can see example in the .env_example file
```
// .env_example

IS_PROD="true"
CONNECTION_STRING_POSTGRESQL="user=xxxx password=xxxxx dbname=xxxxxx port=5433 sslmode=disable"
CONNECTION_STRING_POSTGRESQL_PROD="host=/cloudsql/xxxxxx:xxxxxx user=xxxxxxx password=xxxxxxxx dbname=xxxxxx sslmode=disable"

GO_API_PORT=3000
GO_API_PORT_PROD=8080

AE_NODE_URL="http://localhost:3001"
AE_NODE_URL_PROD="xxxxxxx"

SECRET_KEY="AE_SECRET_KEY" 
CONTRACT_SOURCE_URL_GIT_RAW="https://raw.githubusercontent.com/your_contractg_url.aes"

AE_CONTRACT_TOKEN_MIGRATION_ADDRESS="smart_contract_address"

AE_COMPILER_URL="http://localhost:3080"
AE_COMPILER_URL_PROD="xxxxxxx"

AE_NETWORK_ID="ae_devnet"
AE_NETWORK_ID_PROD="ae_devnet"
# AE_NETWORK_ID_PROD="ae_uat"

AE_BACKEND="fate"
AE_ABI_VERSION=3

BACKENDLESS_LOGIN="xxxxxx"
BACKENDLESS_PASSWORD="xxxxxxx."
BACKENDLESS_ID="xxxxxx"
BACKENDLESS_KEY="xxxxx"
BACKENDLESS_URL="xxxxxxx"
BACKENDLESS_USERTOKEN="xxxxx"
BACKENDLESS_TABLE="xxxxx"

BEARER_AUTH_TOKEN="Bearer xxxxx"
BEARER_AUTH_TOKEN_PROD="Bearer xxxxxx"
```

and start it `go run app.go`

#### There are several `routes` that can be access
`/` - GET tree status. returns merkle tree root hash and number of leafs, nodes.
``` 
response
{
    "status": true,
    "tree": {
        "root": "20B4C63E8063464DE5EF6CC60122AC3138F413A53CED28C641BD7867B76F52B9",
        "length": 301378
    }
}
```


`/info/{ethAddress}` - GET info by given ethereum address. Returns index, hash, amount of tokens and migration status of current leaf, and if it is migrated tx hash 
``` 
response: 
{
    "index": 17,
    "hash": "5C73535E4E3A596B439554FC5246AF5E9307AB259E6D00D131A1A9422BE352AA",
    "tokens": "896946881386313856",
    "migrated": true,
    "migrateTxHash": "th_2RWiuYoLTVorP8XCdu7yzfJAZ2eThEUwn6XtVy9W7aaU1CijxW"
}
```


`/hash/{index}` - GET hash by given leaf index. Returns it's hash
```
response:
{
    "index": 1,
    "hash": "B4E1FC7C12705A751908BA6438B77342DA68BFC322E346744BA3D38D63636FEE"
}
```


`/siblings/{index}` - GET intermediary hashes by given leaf index. Returns array of intermediary hashes
```
response:
{
    "status": true,
    "hashes": [
        "D477BC2283558E13BD236EBC12F00BD41825E07F003CFD1C414EAA61323A9B30",
        "E03C0C82C6073966F29125656A189E477AEBCAB7D3F087492E6ADAA58775031D",
        "5EF94B5DE05D8CD99B7AC33D94767FC38A80FF9E935100DFA501A038953042E1",
        "27C8F150F0FF3C98E2E5449FD8CD0DF3F935D4009FE5CBBAECB67C01657A32B4",
        "A8D5C7ADBD530EC96F5F2286ADE61A88A5394F32EB12A3C5E348158295CA2FCB",
        "E7C728C723F22F94BBCA7CAD8738E58E11873D87905875AD99C64EA149CCAD39",
        "A7578FEF2E2993203D438C973FD1BA2FFB7549EB8D9172E643E7ABAE51F3CEA4",
        "8CA2AB18E655A16D9BE1FE4BAC6C37300362213A21F1868F7C067DC7BF42B4EA",
        "0E26EA1CBF30F0556C73F9B77C668775E7227F61C446F33FF4C09FB148485A2F",
        "4140508F328DF0407D8EC70A475C1C771F440A5CD0E1E2AAFF63EA17FC04D284",
        "7A91D1910EA39A9B3F6F3C361C19FF8AACD8B48E94D8A48096BAEFC70C62F10C",
        "C9178C00309D658E133C6FD0E26251E8961F454F772DD4DCF9B52CC477D79900",
        "4BC0DB55DC1B86C79B80D232FD1C8C0A34FE7686761AB05B15F24623B23E52D4",
        "6B1668C4C38B49042ECED27A1A1A5237B49FA562CD94D4FDB27076DC0602E76E",
        "A618432138C49B84735552EE60C4DFCE2E7EBF9161C592554F39C800E155E5C1",
        "C9761373ADDBEEEB73C932B213985FF233C3207D873394D5AF8E8071EA823EA2",
        "AB0FA2604F5F394B0ADFC2AAE55B8296F390A58910E7CC6E1DC031023941A259",
        "9FEF092769B79A4ED4540D43386A4EA6A6B8F03A89DB2E3B7F955817EBA05ED4",
        "16D23EC2BE773B1ABD000772D8FAE6D7502252381E3B21853697FDD0BA0D78B9"
    ]
}
```


`/validate` - POST validate is provided data can generate same merkle root hash. Should pass ethereum address, amount of tokens, leaf index and an array of intermediary hashes. Returns object with boolean property ‘exists’ which validates if the request is valid or not.
```
request body:
{
    "ethAddress": "0x18c4a229411ec44fc0ddfc7fd02e31fc1872a6e1",
    "balance": "449437408529709982023680",
    "index": 2345,
    "hashes": [
        "D28F693728229E4AF6A2C8D263E0F35BAB2B659CA98ADBB24F250017E8FEE16B",
        "C8A76985CC36C37D79A33028537D7B5EBA04CFA51A1AB78E9C6ADCC7FDCBDA02",
        "A8CA3099A8DF1D48E27D8A7C87440594E644C4816E6AA38C57D03FE8AFE8F88C",
        "800079F085CA51B0BC4D0D2E5B22A2B0E3FBA899C6F3A7596D270EFB26367FCF",
        "3AB5113A03BD541A704BFB24C1CE7BEFAF752DF088EF3C4BDEF7C936534E5647",
        "70886EF10DBDF2FDB2CF145EC37BEE95E31BF9DA8444C924F03FFB8EAA63EF98",
        "2FF80709DE5F2ED00142E2647E261A1CF934A0761CB8D14818199269B6E4ECB9",
        "89C68E07F6887E0A9FB6F553A18752C6FB5F28ADAFE7E983B0B8342C93E136F2",
        "62D2E1270D2BD08C51DA2E4A197540658553ACDB767B16AC55F28334C84C5553",
        "A51C2763E3BA7671B9C8868E429FA52916E7FB34A41B471CBBE42703421F1307",
        "C345D339283E1D15B77106B3D3C58C5980B37D4A69414EA634ECADC2CC889778",
        "C74DEC9F3A5556F51D69201CC5C61B3BEE21E04451EEAE1E8590D6CE916FA431"
    ]
}
response:
{
    "status": true,
    "exists": false
}
```


`/migrate` - POST migrate tokens to your AE address. Should pass ethereum address(from provided eth address backend should take leaf index and an array of intermediary hashes), AE address and signature(signed AE address). Returns tx hash and tx status
```
request body:
{
	"ethPubKey": "0xedc6942e1fbbbd8d592123c16e00d8058b396bf2",
	"aeAddress": "ak_tWZrf8ehmY7CyB1JAoBmWJEeThwWnDpU4NadUdzxVSbzDgKjP",
	"signature": "0xf31ee3eaea7e4fd318d7df027a73a06d452b0e89ff5d736e017c0fb638e631051f8d1a1f2a90665ee9f6b2e16757204861a0e3ae51a5674a8ad9f7e73d864c211b"
}

response:
{
    "txHash": "th_4nQmPEjKwke48WkdQeTUyNMuvTGdt92CEhKaJ3mKAcPjppQqM",
    "status": "ok"
}

```


`/owner` - POST add token owner into database, create merkle tree leaf. Should pass ethereum address and amount of tokens. Returns index and hash of leaf
```
request body:
{
	"ethAddress" : "0x4286fF605Da8490775c7C57939a54EA4597F9D18",
	"balance": "45222147440638439718912"
}

response:
{
    "index": 0,
    "hash": "97BE23922EB76D5CAD22BEEC69F4C3B07BA1220C932674D3C7BE8F4051245967",
    "message": "Data was successfully added!"
}
```

## Import token owners (db table backup)

// mac users
1. install brew (https://brew.sh/) `if you have ‘psql’ as env variable skip this step`
2. insttall ‘libpq' `if you have ‘psql’ as env variable skip this step`
```
    brew install libpq
    brew link --force libpq
```
// windows users
// if 'psql' is not recognized in 'CMD', you should manualy set environment path  
- 'THIS PS' right click -> Properties 
- 'Advanced system settings'
- select 'Advanced' tab ->'Environment Variables'
- go to 'System variables' and select/click 'Path' -> EDIT
- 'NEW' -> type/paste your path to PostgreSQL -> 'C:\Program Files\PostgreSQL\12\bin'
- close current CMD and reopen it.


3. Create database. `If you want to use your own database skip this step`
```
    // `localhost (url), 5432 (port), postgres (postgres user)` are defaults of postgresql instance 
    createdb -h localhost -p 5432 -U postgres DATABASE_NAME
```
   
4. Restore database
```
    psql -U postgres -h 127.0.0.1 -p 5432 -d DATABASE_NAME -f ./BACKUP_FILE
```

P.S.: backup script should try to set "usage” rights to 'cloudsqlimportexport’ user, but this user would not exists(almost sure) in your DB and you will see error messages. Table would be imported successfullly.

### linux users - how to install postgreSQL on ubuntu - https://tecadmin.net/install-postgresql-server-on-ubuntu/
1. sudo apt-get install wget ca-certificates
2. wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -
3. sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt/ `lsb_release -cs`-pgdg main" >> /etc/apt/sources.list.d/pgdg.list'
4. sudo apt-get update
5. sudo apt-get install postgresql postgresql-contrib
5. go to '/etc/postgresql/11/main/postgresql.conf' and uncomment this line '#listen_addresses = 'localhost'     # what IP address(es) to listen on;'
 - Success. You can now start the database server using:
```
    pg_ctlcluster 11 main start
```
6. pgAdmin4 instalation https://linoxide.com/linux-how-to/how-install-pgadmin4-ubuntu/
    - sudo apt update -y && sudo apt upgrade -y
    - sudo apt-get install pgadmin4 pgadmin4-apache2
        -- During this setup, you will be prompted for an email address. Provide your preferred email address(username)
        -- provide the password you are going to use during log in
        -- do not forget to wrote down username and pass 
        -- you can connect to PostgreSQL by browsing your server's IP address or domain name followed by the suffix /pgAdmin4  in the URL. (http://127.0.0.1/pgadmin4)


7. Create database
// if you try to connect through pgAdmin4 interface and an error is thrown for invalid password 
// or you try to execute psql command `createdb -h localhost -p 5432 -U postgres test` and again password required or invalid 
// change default password 
```
    sudo -u postgres psql template1
    ALTER USER postgres with encrypted password 'your_password';
```

- After configuring the password, edit the file /etc/postgresql/11/main/pg_hba.conf to use MD5 authentication with the postgres user:
```
    local   all         postgres                          md5
```

- restart the PostgreSQL service to initialize the new configuration 
```
    sudo systemctl restart postgresql.service 
```

- create database
```
    createdb -h localhost -p 5432 -U postgres test
```

8. Restore database
```
    psql -U postgres -h 127.0.0.1 -p 5432 -d test -f ./BACKUP_FILE
```