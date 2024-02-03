import crypto from 'crypto'
import process from 'node:process'

import express from 'express'
import cors from 'cors'
import bodyParser from 'body-parser'
import bcrypt from 'bcrypt'
import { configDotenv } from 'dotenv'

import { setupDatabase, db } from './db/config.mjs'

import {
    FingerprintJsServerApiClient,
    Region,
} from '@fingerprintjs/fingerprintjs-pro-server-api'

configDotenv({path: new URL('../.env', import.meta.url)})

const app = express()

await setupDatabase()

const fpjsClient = new FingerprintJsServerApiClient({
    apiKey: process.env.SERVER_FPJS_API_KEY,
    region: Region.AP
})

app.use(cors())

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }));

app.post('/users/add', async (req, res) => {
    const hash = bcrypt.hashSync(req.body.password, 5);

    const fpjsVisitor = req.body.fpjsVisitor
    
    try {
        const event = await fpjsClient.getEvent(fpjsVisitor.requestId)
        const visitorId = event.products.identification.data.visitorId;

        if (new URL(event.products.identification.data.url).origin !== req.headers["origin"] || fpjsVisitor.visitorId !== visitorId) {
            throw new Error('Bad Request')
        }

        const userAlreadyExists = await new Promise((resolve, reject) => {
            db.get(`select username from users where visitor_id = $visitorId;`, {
                $visitorId: visitorId 
            }, function (err, row) {
                if (err) {
                    reject(err)
                }
                resolve(row)
            })
        })

        if (userAlreadyExists) {
            throw new Error('User already exists!');
        }

        await new Promise((resolve, reject) => {
            db.run(`insert into users values($id, $username, $password, $visitorId);`, {
                $id: crypto.randomUUID(),
                $username: req.body.username,
                $password: hash,
                $visitorId: visitorId
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
        console.log(error)
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
            const fpjsVisitor = req.body.fpjsVisitor
            const event = await fpjsClient.getEvent(fpjsVisitor.requestId)
            const visitorId = event.products.identification.data.visitorId;

            if (new URL(event.products.identification.data.url).origin !== req.headers["origin"] || fpjsVisitor.visitorId !== visitorId) {
                throw new Error('Bad Request')
            }

            if ((Date.now() - event.products.identification.data.timestamp) > 30000) {
                throw new Error('Invalid request')
            }

            const verified = bcrypt.compareSync(password, resultRow.password)

            const validVisitor = await new Promise((resolve, reject) => {
                db.get(`select * from users where username = $username and visitor_id = $visitorId;`, {
                    $username: username,
                    $visitorId: visitorId
                }, function (err, row) {
                    if (err) {
                        reject(err)
                    }
                    resolve(row)
                })
            })
    
            if (verified && validVisitor) {
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
        res.status(500).json({
            success: false,
            message: error.message
        })
    }
})

app.listen(process.env.PORT || 5000, () => {
    console.log(`listening to port ${process.env.PORT || 5000}`)
});
