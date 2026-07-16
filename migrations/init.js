// migrations/init.js
const crypto = require('crypto');
const { MongoClient } = require('mongodb');
require('dotenv').config();
const { ensureMongoIndexes, getMongoConfig } = require('../mongo-config');
const { getDatabaseConfig } = require('../db-config');
const { ElasticDatabase } = require('../elastic-db');

const ADMIN_PERMISSIONS = [
    'checker.run',
    'checker.results',
    'proxy.manage',
    'lists.group',
    'history.own',
    'history.all',
    'users.manage',
    'hosts.manage',
    'sessions.view'
];

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
    const hash = crypto.pbkdf2Sync(String(password), salt, 120000, 32, 'sha256').toString('hex');
    return `${salt}:${hash}`;
}

async function ensureAdminUser(db) {
    const users = db.collection('users');
    const adminUsername = String(process.env.ADMIN_USERNAME || 'admin').trim().toLowerCase();
    const adminPassword = String(process.env.ADMIN_PASSWORD || 'admin123');
    const existingAdmin = await users.findOne({ username: adminUsername });

    if (existingAdmin) {
        console.log(`Admin kullanıcı zaten var: ${adminUsername}`);
        return;
    }

    await users.insertOne({
        username: adminUsername,
        passwordHash: hashPassword(adminPassword),
        role: 'admin',
        permissions: ADMIN_PERMISSIONS,
        active: true,
        createdAt: new Date(),
        updatedAt: new Date(),
        createdBy: 'migration'
    });
    console.log(`Admin kullanıcı oluşturuldu: ${adminUsername}`);
}

async function migrate() {
    const databaseConfig = getDatabaseConfig();

    if (databaseConfig.provider === 'elasticsearch') {
        const config = databaseConfig.elastic;
        const db = new ElasticDatabase(config);
        console.log(`Elasticsearch migration: env=${config.source} indexPrefix=${config.indexPrefix} auth=${config.authMode}`);
        await db.ping();
        await db.ensureSchema();
        await db.collection('settings').updateOne(
            { _id: 'system' },
            {
                $setOnInsert: {
                    allowedHosts: ['localhost', '127.0.0.1'],
                    rootDomains: [],
                    enforceRootDomains: false,
                    proxyConfigs: [],
                    userProxySelections: {},
                    createdAt: new Date()
                },
                $set: { schemaVersion: 1, migratedAt: new Date() }
            },
            { upsert: true }
        );
        await ensureAdminUser(db);
        console.log(`Elasticsearch migration tamamlandı: indexPrefix=${config.indexPrefix}`);
        return;
    }

    const config = databaseConfig.mongo || getMongoConfig();
    const client = new MongoClient(config.uri, config.clientOptions);

    console.log(`MongoDB migration: env=${config.source} db=${config.dbName} auth=${config.authMode}`);

    try {
        await client.connect();
        const db = client.db(config.dbName);
        await db.command({ ping: 1 });

        const indexStatus = await ensureMongoIndexes(db);
        if (!indexStatus.supported) {
            console.warn(`MongoDB migration uyarısı: ${indexStatus.warning}`);
        }

        await db.collection('settings').updateOne(
            { _id: 'system' },
            {
                $setOnInsert: {
                    allowedHosts: ['localhost', '127.0.0.1'],
                    rootDomains: [],
                    enforceRootDomains: false,
                    proxyConfigs: [],
                    userProxySelections: {},
                    createdAt: new Date()
                },
                $set: { schemaVersion: 1, migratedAt: new Date() }
            },
            { upsert: true }
        );
        await ensureAdminUser(db);

        console.log(`MongoDB migration tamamlandı: db=${db.databaseName}`);
    } finally {
        await client.close();
    }
}

migrate().catch(error => {
    console.error(`DB migration başarısız: ${error.message}`);
    process.exit(1);
});
