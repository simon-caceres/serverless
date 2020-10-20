const express = require('express')
const crypto = require('crypto')
const Users = require('../models/User')
const jwt = require('jsonwebtoken')
const {isAuthenticated} = require('../auth/index')


const router = express.Router()

const signToken = (_id) => {
    return jwt.sign({_id}, 'my-secret', {
        expiresIn: 60 * 60 * 24 * 365
    })
}


router.post('/register', (req, res) => {
    const {email, password} = req.body
    crypto.randomBytes(16, (err, salt) => {
        const newSalt = salt.toString('base64')
        crypto.pbkdf2(password, newSalt, 100, 64, 'sha1', (err, key) => {
            const encryptPassword = key.toString('base64')
            Users.findOne({ email}).exec()
                .then(user => {
                    if (user) {
                        return res.send('usuario ya existe')
                    }
                    Users.create({
                        email,
                        password: encryptPassword,
                        salt: newSalt
                    }).then(() => {
                        res.send('usuario creado con exito')
                    })
                })
        })
    })
})

router.post('/login', (req, res) => {
  const {email, password} = req.body
  Users.findOne({email}).exec()
        .then(user => {
            if(!user) {
                res.send('usuario y/o contraseña incorrecto')
            }
            crypto.pbkdf2(password, user.salt, 100, 64, 'sha1', (err, key) => {
                const encryptPassword = key.toString('base64')
                if(user.password === encryptPassword) {
                    const token = signToken(user._id)
                    return res.send({token})
                }
                return res.send('usuario y/o contraseña incorrecto')
            })
        })
})

router.put('/:id', (req, res) => {
    Users.findByIdAndUpdate(req.params.id, req.body)
        .then(() => res.sendStatus(204))
})

router.delete('/:id', (req, res) => {
    Users.findOneAndDelete(req.params.id)
        .exec()
        .then(() => res.sendStatus(204))
})

router.get('/me', isAuthenticated, (req, res) => {
    res.send(req.user)
})


module.exports = router