package postgres

import (
	"database/sql"
	"fmt"
	// "github.com/LimeChain/merkletree"
	merkletree "aepp-token-migration-backend/types"
	_ "github.com/lib/pq"
	"sync"
)

const (
	InsertQuery       = `INSERT INTO token_migration (hash, eth_address, ae_address, balance, leaf_index) 
						 VALUES ($1, $2, $3, $4, $5)`
	SelectQuery       = "SELECT hash FROM token_migration ORDER BY leaf_index"
	CreateQuery       = `CREATE TABLE token_migration (
		hash varchar(66) NOT NULL,
		eth_address varchar(42) NOT NULL,
		ae_address varchar(53) DEFAULT '',
		balance varchar(100),
		leaf_index int,
		PRIMARY KEY (hash)
	  )` // 53 ?
	CreateIfNotExists = `CREATE TABLE IF NOT EXISTS token_migration (
		hash varchar(66) NOT NULL,
		eth_address varchar(42) NOT NULL,
		ae_address varchar(53) DEFAULT '',
		balance varchar(100),
		leaf_index int,
		PRIMARY KEY (hash)
	  )` // 53 ?
	QueryGetByEthAddress = `SELECT * FROM token_migration
	where lower(eth_address) = $1`
)

type PostgresMerkleTree struct {
	merkletree.FullMerkleTree
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
	_, err := tree.db.Exec(InsertQuery, hash, ethAddress, aeAddress, balance, leafIndex)
	if err != nil {
		fmt.Println("==> Error:")
		fmt.Println(err.Error())
	}
}

// LoadMerkleTree takes an implementation of Merkle tree and postgre connection string
// Augments the tree with db saving
// returns a pointer to an initialized PostgresMerkleTree
func LoadMerkleTree(tree merkletree.FullMerkleTree, connStr string) *PostgresMerkleTree {

	db := connectToDb(connStr)
	
	createHashesTable(db)

	getAndInsertStoredHashes(db, tree)

	postgresMemoryTree := PostgresMerkleTree{}
	postgresMemoryTree.db = db
	postgresMemoryTree.FullMerkleTree = tree

	return &postgresMemoryTree
}

func connectToDb(connStr string) *sql.DB {
	db, err := sql.Open("postgres", connStr)
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

func getAndInsertStoredHashes(db *sql.DB, tree merkletree.InternalMerkleTree) {
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
		// fmt.Printf("==> hash from db: %s\n", hash)
	}

	tree.Recalculate()
}

// Get additional info from Db by given ethAddress
func (tree *PostgresMerkleTree) GetByEthAddress(ethAddress string) (hash string, leaf_index int, balance string, ae_address string){
	rows, err := tree.db.Query(QueryGetByEthAddress, ethAddress)
	if err != nil {
		panic("Could not query the stored hashes.\n Original error: " + err.Error())
	}

	for rows.Next() {
		var eth_address string


		err = rows.Scan(&hash, &eth_address, &ae_address, &balance, &leaf_index)
		if err != nil {
			panic("Could not scan the stored hashes.\n Original error: " + err.Error())
		}
	}

	return hash, leaf_index, balance, ae_address
}
