const mongoose = require("mongoose");
const passportLocalMongoose = require("passport-local-mongoose");

const UserSchema = new mongoose.Schema({
    username: String,
    password: String,
    email: String,
    phone: Number
});

UserSchema.plugin(passportLocalMongoose);

module.exports = mongoose.model("User", UserSchema);