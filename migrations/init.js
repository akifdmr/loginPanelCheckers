// migrations/init.js
const { MongoClient } = require('mongodb');
const crypto = require('crypto');
require('dotenv').config();

// Atlas connection string'ini kullan
const uri = process.env.MONGODB_CONNECTIONSTRING;
if (!uri) {
    console.error('❌ MONGODB_CONNECTIONSTRING tanımlı değil!');
    process.exit(1);
}

const client = new MongoClient(uri);

// ... mevcut migration kodu ...