import express from "express";
import Database from 'better-sqlite3';
import bcrypt from "bcrypt"

const db = new Database('ourApp.db');
db.pragma('journal_mode = WAL');

// seting up database
const createTables = db.transaction(() => {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL
        )
        `).run()
})

createTables()


const app = express()
app.set("view engine", "ejs")
app.use(express.urlencoded({ extended: false }))
app.use(express.static("public"))

// middleware: getting in the middle of a request
app.use(function (req, res, next) {
    res.locals.errors = []
    next()
})

app.get("/", (req, res) => {
    res.render("homepage")
})

app.get("/login", (req, res) => {
    res.render("login")
})

app.post("/register", (req, res) => {
    const errors = []

    if (typeof req.body.username !== "string") req.body.username = ""
    if (typeof req.body.password !== "string") req.body.password = ""

    // username
    req.body.username = req.body.username.trim()

    if (!req.body.username) errors.push("You must provide a username")
    if (req.body.username && req.body.username.length < 3) errors.push("Your username must be at least 3 characters")
    if (req.body.username && req.body.username.length > 10) errors.push("Your username must be less than 10 characters")
    if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only contain letters and numbers")

    // password
    req.body.password = req.body.password.trim()

    if (!req.body.password) errors.push("You must provide a password")
    if (req.body.password && req.body.password.length < 8) errors.push("Your password must be at least 8 characters")
    if (req.body.password && req.body.password.length > 70) errors.push("Your password must be less than 70 characters")

    if (errors.length) {
        return res.render("homepage", { errors })
    }

    // save new user into a database
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password, salt)

    const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
    ourStatement.run(req.body.username, req.body.password)

    // log the user in by giving them a cookie
    res.send("Thank you for filling out the form.")

    // console.log("req:", req)
    // console.log("req.body:", req.body)
    // console.log("HEELO")

})

app.listen(3000)