const MONGO_URI_ENV_KEYS = [
    'DATABASE_URL',
    'MONGODB_URI',
    'MONGODB_CONNECTIONSTRING',
    'MONGO_URL',
    'MONGODB_URL'
];

function cleanEnvValue(value) {
    const trimmed = String(value || '').trim();
    if (!trimmed) return '';
    if (trimmed === '...' || /^<.*>$/.test(trimmed) || /^your[_-]/i.test(trimmed)) return '';
    return trimmed.replace(/^['"]|['"]$/g, '');
}

function getMongoConfig(env = process.env) {
    const source = MONGO_URI_ENV_KEYS.find(key => cleanEnvValue(env[key]));
    const uri = source ? cleanEnvValue(env[source]) : '';
    const username = cleanEnvValue(env.MONGODB_USERNAME);
    const password = cleanEnvValue(env.MONGODB_PASSWORD);
    const configuredDbName = cleanEnvValue(env.MONGODB_DB_NAME || env.MONGODB_NAME || env.DB_NAME);

    if (!uri) {
        throw new Error(`MongoDB connection string missing (${MONGO_URI_ENV_KEYS.join(', ')})`);
    }

    let parsed;
    try {
        parsed = new URL(uri);
    } catch {
        throw new Error(`${source} is not a valid MongoDB connection string`);
    }

    if (!['mongodb:', 'mongodb+srv:'].includes(parsed.protocol)) {
        throw new Error(`${source} must use mongodb:// or mongodb+srv://`);
    }

    const uriHasCredentials = Boolean(parsed.username || parsed.password);
    if (!uriHasCredentials && Boolean(username) !== Boolean(password)) {
        throw new Error('MONGODB_USERNAME and MONGODB_PASSWORD must be configured together');
    }

    const databaseFromUri = decodeURIComponent(parsed.pathname.replace(/^\//, ''));
    const clientOptions = {
        serverSelectionTimeoutMS: Number(env.MONGODB_SERVER_SELECTION_TIMEOUT_MS || 15000)
    };

    if (!uriHasCredentials && username && password) {
        clientOptions.auth = { username, password };
    }

    const certPath = cleanEnvValue(env.MONGODB_CERT_PATH);
    if (parsed.searchParams.get('authMechanism') === 'MONGODB-X509' && certPath) {
        clientOptions.tlsCertificateKeyFile = certPath;
        clientOptions.tlsAllowInvalidCertificates = false;
    }

    return {
        uri,
        source,
        dbName: configuredDbName || databaseFromUri || 'cloverapp',
        clientOptions,
        authMode: uriHasCredentials ? 'uri' : clientOptions.auth ? 'environment' : 'none'
    };
}

async function ensureMongoIndexes(db) {
    const indexOperations = [
        () => db.collection('users').createIndex({ username: 1 }, { unique: true }),
        () => db.collection('check_results').createIndex({ ownerUserId: 1, createdAt: -1 }),
        () => db.collection('successful_logins').createIndex({ ownerUserId: 1, createdAt: -1 }),
        () => db.collection('session_logs').createIndex({ createdAt: -1 }),
        () => db.collection('session_logs').createIndex({ username: 1, createdAt: -1 }),
        () => db.collection('user_audit_logs').createIndex({ createdAt: -1 }),
        () => db.collection('settings').createIndex({ _id: 1 })
    ];

    try {
        await Promise.all(indexOperations.map(operation => operation()));
        return { supported: true };
    } catch (error) {
        if (error.code === 59 || /createIndexes not found/i.test(error.message)) {
            return { supported: false, warning: 'MongoDB provider does not support createIndexes' };
        }
        throw error;
    }
}

module.exports = {
    MONGO_URI_ENV_KEYS,
    cleanEnvValue,
    getMongoConfig,
    ensureMongoIndexes
};
