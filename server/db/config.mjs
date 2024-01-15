import sqlite3 from 'sqlite3'

const sqlite = sqlite3.verbose()
const db = new sqlite.Database('server/db/users.db', (err) => {
    if (err) {
        throw err
    }
})

const setupDatabase = () => {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            db.run(`CREATE TABLE IF NOT EXISTS users(
                id uuid NOT NULL UNIQUE,
                username VARCHAR NOT NULL UNIQUE,
                password NVARCHAR NOT NULL
            );`, function (err) {
                if (err) {
                    reject(`Failed to create database\n ${err}`)
                }
                resolve()
            })
            // db.run(`DELETE FROM users;`, function (err) {
            //     if (err) {
            //         reject(`Failed to clear users table\n ${err}`)
            //     }
            //     resolve()
            // })
        })
    })
}

export { setupDatabase, db }