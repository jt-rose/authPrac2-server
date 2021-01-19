/* --------------------------------- imports -------------------------------- */

require('dotenv').config()

import express from 'express'
import bodyParser from 'body-parser'
import cookieParser from 'cookie-parser'
import session from 'express-session'
import cors from 'cors'
import helmet from 'helmet'
import logger from 'morgan'

import bcrypt from 'bcrypt'

/* ------------------------------- middleware ------------------------------- */

const app = express()
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({
    extended: true
}))
app.use(cookieParser())
app.use(logger('dev'))
app.use(helmet())
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}))
app.use(session({
    secret: process.env.SESSION_SECRET as string,
    resave: false,
    saveUninitialized: false,
}))

/* --------------------------------- mock DB -------------------------------- */

class User {
    username: string;
    password: string;
    constructor(username: string, password: string) {
        this.username = username;
        this.password = password
    }
}

let mockDB: User[] = [
    {
        username: 'abc',
        password: 'abc'
    }
]


const findUser = (username: string) => mockDB.find(user => user.username === username)

const addUser = async (username: string, password: string) => {
    const hashedPassword = await bcrypt.hash(password, 12)
    const newUser = new User(username, hashedPassword)
    mockDB.push(newUser)
}

class ServerSession {
    username: string;
    cookieValue: string;

    constructor(username: string, cookieValue: string) {
        this.username = username
        this.cookieValue = cookieValue
    }
}
let mockServerSessions: ServerSession[] = []

/* --------------------------------- routes --------------------------------- */

app.get('/', (req, res) => {
    res.send('thanks for stopping by!')
})

app.post('/register', async (req, res) => {
    const { username, password } = req.body
    if (findUser(username)) {
        res.json({
            error: true,
            type: 'user already exists'
        })
        return
    }
    await addUser(username, password)
    const cookieValue = await bcrypt.hash(username, 12)
    mockServerSessions.push( new ServerSession( username, cookieValue))
    res.cookie('user', cookieValue, { secure: false}).json({
        error: false,
        type: 'user registered'
    })
    // auto auth
    
    // add try catch

})

app.post('/login', async (req, res) => {
    const { username, password } = req.body
    const user = findUser(username)
    if (!user) {
        res.json({
            error: true,
            type: 'no user found'
        })
        return
    }
    const correctPassword = await bcrypt.compare(password, user.password)
    if (!correctPassword) {
        res.json({
            error: true,
            type: 'wrong password'
        })
        return
    }
    //pass auth
    const cookieValue = await bcrypt.hash(username, 12)// username or random?
    mockServerSessions.push( new ServerSession(username, cookieValue))
    res.cookie('user', cookieValue, { secure: false}).json({error: false, type: 'logged in'})
    

})

app.delete('/logout', (req, res) => {
    res.clearCookie('user').send(200)

    mockServerSessions = mockServerSessions
    .filter(x => x.cookieValue !== req.cookies.user)
//try catch

})

app.get('/protected', (req, res) => {
    console.log(req.cookies)
    const cookie = req.cookies.user ?? null
    if (cookie) {
        const user = mockServerSessions.find(x => x.cookieValue === cookie)
        if (user) {
            res.status(200).json({
                authenticated: true,
                message: 'the valid user is ' + user.username
            })
        }
    } else {
        res.status(401).json({
            authenticated: false,
            message: 'need to login'
        })
    }
})

/* ------------------------------ start server ------------------------------ */

app.listen(4000, () => {
    console.log('listening on port 4000')
})