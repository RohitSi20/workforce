var mongoose = require('mongoose');
var Schema = mongoose.Schema,
bcrypt = require('bcrypt'),
SALT_WORK_FACTOR = 10;

var UserSchema = new Schema({
  _id: mongoose.Schema.Types.ObjectId,
  wemail: {
    type: String,
    required: true,
    unique: true,
    match: /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/
  },
  wpassword: {
    type: String,
    required: true
  },
  wname: {
    type: String,
    required: true
  },
  wdob: {
    type: Date,
    required: true
  },
  wage: {
    type: Number,
    required: true
  },
  waddress: {
    type: String,
    required: true
  },
  wnearcity: {
    type: String,
    required: true
  },
  wstate: {
    type: String,
    required: true
  },
  wpincode: {
    type: Number,
    required: true
  },
  wmobile: {
    type: Number,
    required: true
  },
  woccupation: {
    type: String,
    required: true
  },
  wexperience: {
    type: Number,
    required: true
  },
  wskill: {
    type: String,
    required: true
  },
  wSecQue: {
    type: String,
    required: true
  },
  wSecAns: {
    type: String,
    required: true
  },
  wadhaar: {
    type: Number,
    required: true
  }

});

UserSchema.pre('save', function(next) {
  var user = this;

  
  if (!user.isModified('password')) return next();

  
  bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt) {
      if (err) return next(err);

      
      bcrypt.hash(user.password, salt, function(err, hash) {
          if (err) return next(err);

          // override the cleartext password with the hashed one
          user.password = hash;
          next();
      });
  });
});

UserSchema.methods.comparePassword = function(candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
      if (err) return cb(err);
      cb(null, isMatch);
  });
};


module.exports = mongoose.model('user', UserSchema);
