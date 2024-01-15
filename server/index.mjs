import crypto from 'crypto'
import process from 'node:process'

import express from 'express'
import cors from 'cors'
import bodyParser from 'body-parser'
import bcrypt from 'bcrypt'

import { setupDatabase, db } from './db/config.mjs'

const app = express()

await setupDatabase()

await (
    function () {
        return new Promise((resolve, reject) => {
            db.all(`select * from users;`, (err, rows) => {
                if (err) {
                    reject(`Failed to get data\n ${err}`)
                }
                console.log(rows);
                resolve(rows)
            })
        })
    }
)();

app.use(cors())

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }));

app.post('/users/add', async (req, res) => {
    const hash = bcrypt.hashSync(req.body.password, 5);

    try {
        await new Promise((resolve, reject) => {
            db.run(`insert into users values($id, $username, $password);`, {
                $id: crypto.randomUUID(),
                $username: req.body.username,
                $password: hash
            }, function (error) {
                if (error) {
                    reject(error)
                }
                resolve()
            })
        })
        res.status(200).json({
            success: true,
            message: `Inserted user ${req.body.username}`
        })
    } catch (error) {
        console.log(error.message)
        res.status(500).json({
            success: false,
            message: `Oops! Failed to sign up.`
        })
    }
})

app.post('/users/auth', async (req, res) => {
    const { username, password } = req.body
    try {
        const resultRow = await new Promise((resolve, reject) => {
            db.get(`select username, password from users where username = $username;`, {
                $username: username 
            }, function (err, row) {
                if (err) {
                    reject(err)
                }
                resolve(row)
            })
        })

        if (!resultRow) {
            res.status(500).json({
                success: false,
                message: `No user found.`
            })
        } else {
            const verified = bcrypt.compareSync(password, resultRow.password)
    
            if (verified) {
                res.status(200).json({
                    success: true,
                    message: `Logged in as ${req.body.username}`
                })
            } else {
                res.status(500).json({
                    success: false,
                    message: `Incorrect password.`
                })
            }
        }
    } catch (error) {
        console.error(error)
        res.status(500).json({
            success: false,
            message: error.message
        })
    }
})

app.listen(process.env.PORT || 5000, () => {
    console.log(`listening to port ${process.env.PORT || 5000}`)
});
