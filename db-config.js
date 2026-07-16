const { cleanEnvValue, getMongoConfig } = require('./mongo-config');

const ELASTIC_URL_ENV_KEYS = [
    'ELASTICSEARCH_URL',
    'ELASTIC_URL',
    'ELASTICSEARCH_ENDPOINT',
    'ELASTIC_ENDPOINT',
    'ELK_ENDPOINT'
];

function getDbProvider(env = process.env) {
    const explicit = cleanEnvValue(env.DB_PROVIDER || env.DATABASE_PROVIDER).toLowerCase();
    if (explicit) return explicit;
    if (ELASTIC_URL_ENV_KEYS.some(key => cleanEnvValue(env[key]))) return 'elasticsearch';
    return 'mongodb';
}

function firstCleanEnv(env, keys) {
    for (const key of keys) {
        const value = cleanEnvValue(env[key]);
        if (value) return value;
    }
    return '';
}

function getElasticConfig(env = process.env) {
    const source = ELASTIC_URL_ENV_KEYS.find(key => cleanEnvValue(env[key]));
    const url = source ? cleanEnvValue(env[source]) : '';

    if (!url) {
        throw new Error(`Elasticsearch URL missing (${ELASTIC_URL_ENV_KEYS.join(', ')})`);
    }

    let parsed;
    try {
        parsed = new URL(url);
    } catch {
        throw new Error(`${source} is not a valid Elasticsearch URL`);
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) {
        throw new Error(`${source} must use http:// or https://`);
    }

    const apiKey = firstCleanEnv(env, ['ELASTICSEARCH_API_KEY', 'ELASTIC_API_KEY', 'ELK_APIKEY', 'ELK_API_KEY']);
    const username = firstCleanEnv(env, ['ELASTICSEARCH_USERNAME', 'ELASTIC_USERNAME', 'ELK_USERNAME']);
    const password = firstCleanEnv(env, ['ELASTICSEARCH_PASSWORD', 'ELASTIC_PASSWORD', 'ELK_PASSWORD']);
    if (!apiKey && Boolean(username) !== Boolean(password)) {
        throw new Error('ELASTICSEARCH_USERNAME and ELASTICSEARCH_PASSWORD must be configured together');
    }

    return {
        url: parsed.toString().replace(/\/+$/, ''),
        source,
        indexPrefix: cleanEnvValue(env.ELASTICSEARCH_INDEX_PREFIX || env.ELASTIC_INDEX_PREFIX) || 'loginpanelchecker',
        apiKey,
        username,
        password,
        requestTimeoutMS: Number(env.ELASTICSEARCH_REQUEST_TIMEOUT_MS || 15000),
        authMode: apiKey ? 'apiKey' : username ? 'basic' : 'none'
    };
}

function getDatabaseConfig(env = process.env) {
    const provider = getDbProvider(env);
    if (provider === 'elasticsearch' || provider === 'elastic') {
        return { provider: 'elasticsearch', elastic: getElasticConfig(env) };
    }
    if (provider === 'mongodb' || provider === 'mongo') {
        return { provider: 'mongodb', mongo: getMongoConfig(env) };
    }
    throw new Error(`Unsupported DB_PROVIDER: ${provider}`);
}

module.exports = {
    ELASTIC_URL_ENV_KEYS,
    getDbProvider,
    getElasticConfig,
    getDatabaseConfig
};
