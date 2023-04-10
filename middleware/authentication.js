const User = require('../models/User')
const { UnauthenticatedError } = require('../errors')
const jwt = require('jsonwebtoken')
require('dotenv').config()

const auth = async(req,res,next) => {
    const authHeader = req.headers.authorization
    if(!authHeader || !authHeader.startsWith('Bearer'))
        throw new UnauthenticatedError('Authenication Invalid')
    
    const token = authHeader.split(' ')[1]

    try{
        const payload = jwt.verify(token, process.env.JWT_SECRET)

        // attach the user to access the job routes

        // another way the user object is attached is by finding it from the database
        // we remove the password by using -password
        // const user = User.findById(payload.id).select('-password')
        // req.user = user

        // no need to provide name, we are just doing it for testing
        req.user = { userId: payload.userId, name: payload.name }
        next()
    } catch(error) {
        throw new UnauthenticatedError(error.message)
    }

}

module.exports = auth