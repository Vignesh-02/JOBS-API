const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Please provide name'],
        minlength: 3,
        maxLength: 48
    },
    email: {
        type: String,
        required: [true, 'Please provide email'],
        match: [
            /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
            'Please provide a valid email',
        ],
        unique: true
    },
    password: {
        type: String,
        required: [true, 'Please provide password'],
        minlength: 6
    },
})

UserSchema.pre('save', async function(next){
    const salt = await bcrypt.genSalt(10)
    this.password = await bcrypt.hash(this.password, salt)
    next() 
})

// this.name points to the name in the curremt mongoose.model('User')
UserSchema.methods.createJWT =async function(){
    return await jwt.sign({ userId: this._id, name: this.name },
        process.env.JWT_SECRET, { expiresIn: process.env.JWT_LIFETIME })

}


UserSchema.methods.comparePassword = async function (loginPassword){
    const isMatch = await bcrypt.compare( loginPassword, this.password )
    return isMatch
}
module.exports = mongoose.model('User', UserSchema)