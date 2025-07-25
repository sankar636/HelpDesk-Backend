import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'

const app = express()

app.use(cors({
    origin: 'https://help-desk-frontend-mqmq.vercel.app',
    credentials: true
}))

app.use(express.json({
    limit:"16kb"
}))
app.use(express.urlencoded({
    extended:true,
    limit: "16kb"
}))

app.use(express.static("public"))

app.use(cookieParser())

import userRouter from './Routes/User.routes.js'

app.use('/user', userRouter)

export { app }