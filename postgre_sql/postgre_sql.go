package postgres

import (
	"database/sql"
	"fmt"
	"log"

	types "aepp-token-migration-backend/types"
	"sync"

	_ "github.com/lib/pq"
)

const (
	InsertQuery = `INSERT INTO token_migration (hash, eth_address, ae_address, balance, leaf_index, migrated) 
						 VALUES ($1, $2, $3, $4, $5, $6)`
	SelectQuery = "SELECT hash FROM token_migration ORDER BY leaf_index"
	CreateQuery = `CREATE TABLE token_migration (
		hash varchar(66) NOT NULL,
		eth_address varchar(42) NOT NULL,
		ae_address varchar(53) DEFAULT '',
		balance varchar(100),
		leaf_index int,
		migrated bit NOT NULL,
		migrate_tx_hash varchar(100) DEFAULT '',
		PRIMARY KEY (hash)
	  )`  
	CreateIfNotExists = `CREATE TABLE IF NOT EXISTS token_migration (
		hash varchar(66) NOT NULL,
		eth_address varchar(42) NOT NULL,
		ae_address varchar(53) DEFAULT '',
		balance varchar(100),
		leaf_index int,
		migrated bit NOT NULL,
		migrate_tx_hash varchar(100) DEFAULT '',
		PRIMARY KEY (hash)
	  )`  
	QueryGetByEthAddress = `SELECT * FROM token_migration
	where lower(eth_address) = lower($1)`
	QuerySetMigratedToSuccess = `UPDATE public.token_migration
	SET migrated = '1', migrate_tx_hash = $2, ae_address = $3
	WHERE lower(eth_address) = lower($1);`
	QueryResetMigrationStatus = `UPDATE public.token_migration
	SET migrated = '0', migrate_tx_hash = '', ae_address = ''
	WHERE lower(eth_address) = lower($1);`
)

type PostgresMerkleTree struct {
	types.FullMerkleTree
	db    *sql.DB
	mutex sync.Mutex
}

// Add data to merkle tree and db
func (tree *PostgresMerkleTree) Add(data []byte, ethAddress string, balance string, aeAddress string) (index int, hash string) {
	tree.mutex.Lock()
	index, hash = tree.FullMerkleTree.Add(data)
	tree.addDataToDB(hash, ethAddress, aeAddress, balance, index)
	tree.mutex.Unlock()
	return index, hash
}

func (tree *PostgresMerkleTree) addHashToDB(hash string) {
	_, err := tree.db.Exec(InsertQuery, hash)
	if err != nil {
		fmt.Println(err.Error())
	}
}

func (tree *PostgresMerkleTree) addDataToDB(hash string, ethAddress string, aeAddress string, balance string, leafIndex int) {
	_, err := tree.db.Exec(InsertQuery, hash, ethAddress, aeAddress, balance, leafIndex, 0)
	if err != nil {
		log.Println(err.Error())
	}
}

// SetMigratedToSuccess when tx is mined, migrated will be set to TRUE
func (tree *PostgresMerkleTree) SetMigratedToSuccess(ethAddress string, txHash string, aeAddress string) {
	if ethAddress == "" || txHash == "" || aeAddress == "" {
		log.Printf("[SetMigratedToSuccess] Invalid attempt to set migration status! eth address: %s, tx hash: %s, ae address: %s", ethAddress, txHash, aeAddress)
		return
	}

	tree.mutex.Lock()
	_, err := tree.db.Exec(QuerySetMigratedToSuccess, ethAddress, txHash, aeAddress)
	if err != nil {
		log.Printf("[SetMigratedToSuccess] ", err.Error())
	}

	tree.mutex.Unlock()
}

// ResetMigrationStatus develop route, reset migration status to FALSE, delete tx_hash and ae address
func (tree *PostgresMerkleTree) ResetMigrationStatus(ethAddress string) {
	if ethAddress == ""  {
		log.Printf("[SetMigratedToSuccess] Invalid attempt to set migration status! eth address: %s", ethAddress)
		return
	}

	tree.mutex.Lock()
	_, err := tree.db.Exec(QueryResetMigrationStatus, ethAddress)
	if err != nil {
		log.Printf("[ResetMigrationStatus] ", err.Error())
	}

	tree.mutex.Unlock()
}

// LoadMerkleTree takes an implementation of Merkle tree and postgre connection string
// Augments the tree with db saving
// returns a pointer to an initialized PostgresMerkleTree
func LoadMerkleTree(tree types.FullMerkleTree, connStr string) *PostgresMerkleTree {

	db := connectToDb(connStr)

	createHashesTable(db)

	getAndInsertStoredHashes(db, tree)

	postgresMemoryTree := PostgresMerkleTree{}
	postgresMemoryTree.db = db
	postgresMemoryTree.FullMerkleTree = tree

	return &postgresMemoryTree
}

func connectToDb(connStr string) *sql.DB {

	fmt.Println(connStr)

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable",
		"token-migration:europe-west1:test-token-db-p",
		"token-migration",
		"A2DMFlwEDj85ep6JJJJ",
		"test")

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		panic("Could not connect to the database.\n Original error: " + err.Error())
	}
	return db
}

func createHashesTable(db *sql.DB) {
	_, err := db.Exec(CreateIfNotExists)
	if err != nil {
		panic("Could not create the table in the db.\n Original error: " + err.Error())
	}
}

func getAndInsertStoredHashes(db *sql.DB, tree types.InternalMerkleTree) {
	rows, err := db.Query(SelectQuery)
	if err != nil {
		panic("Could not query the stored hashes.\n Original error: " + err.Error())
	}

	for rows.Next() {
		var hash string
		err = rows.Scan(&hash)
		if err != nil {
			panic("Could not scan the stored hashes.\n Original error: " + err.Error())
		}

		tree.RawInsert(hash)
	}

	tree.Recalculate()
}

// Get additional info from Db by given ethAddress
func (tree *PostgresMerkleTree) GetByEthAddress(ethAddress string) types.MigrationInfo {
	rows, err := tree.db.Query(QueryGetByEthAddress, ethAddress)
	if err != nil {
		panic("Could not query the stored hashes.\n Original error: " + err.Error())
	}

	var info types.MigrationInfo

	for rows.Next() {
		err = rows.Scan(&info.Hash, &info.Eth_address, &info.Ae_address, &info.Balance, &info.Leaf_index, &info.Migrated, &info.Migrate_tx_hash)
		if err != nil {
			panic("Could not scan the stored hashes.\n Original error: " + err.Error())
		}
	}

	return info
}
