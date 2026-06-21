// migrations/init.js
const { MongoClient } = require('mongodb');
require('dotenv').config();
const { ensureMongoIndexes, getMongoConfig } = require('../mongo-config');

async function migrate() {
    const config = getMongoConfig();
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

        console.log(`MongoDB migration tamamlandı: db=${db.databaseName}`);
    } finally {
        await client.close();
    }
}

migrate().catch(error => {
    console.error(`MongoDB migration başarısız: ${error.message}`);
    process.exit(1);
});
