const { ObjectId } = require('mongodb');

const COLLECTIONS = [
    'users',
    'check_results',
    'successful_logins',
    'session_logs',
    'user_audit_logs',
    'settings'
];

function normalizeId(value) {
    if (value == null) return '';
    if (typeof value === 'object' && value.toHexString) return value.toHexString();
    return String(value);
}

function serialize(value) {
    if (value instanceof Date) return value.toISOString();
    if (value && typeof value === 'object' && value.toHexString) return value.toHexString();
    if (Array.isArray(value)) return value.map(serialize);
    if (value && typeof value === 'object') {
        return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, serialize(item)]));
    }
    return value;
}

function setPath(target, dottedPath, value) {
    const parts = dottedPath.split('.');
    let cursor = target;
    for (let i = 0; i < parts.length - 1; i++) {
        const key = parts[i];
        if (!cursor[key] || typeof cursor[key] !== 'object' || Array.isArray(cursor[key])) cursor[key] = {};
        cursor = cursor[key];
    }
    cursor[parts[parts.length - 1]] = value;
}

function unsetPath(target, dottedPath) {
    const parts = dottedPath.split('.');
    let cursor = target;
    for (let i = 0; i < parts.length - 1; i++) {
        cursor = cursor && cursor[parts[i]];
        if (!cursor || typeof cursor !== 'object') return;
    }
    delete cursor[parts[parts.length - 1]];
}

function getPath(target, dottedPath) {
    return dottedPath.split('.').reduce((cursor, key) => cursor && cursor[key], target);
}

function applyProjection(doc, projection) {
    if (!doc || !projection) return doc;
    const next = { ...doc };
    for (const [key, enabled] of Object.entries(projection)) {
        if (enabled === 0 || enabled === false) delete next[key];
    }
    return next;
}

function sourceWithoutId(document) {
    const { _id, ...source } = document || {};
    return source;
}

class ElasticCursor {
    constructor(collection, query, options = {}) {
        this.collection = collection;
        this.query = query || {};
        this.options = options || {};
        this.sortSpec = null;
        this.limitCount = 1000;
    }

    sort(sortSpec) {
        this.sortSpec = sortSpec;
        return this;
    }

    limit(limitCount) {
        this.limitCount = limitCount;
        return this;
    }

    async toArray() {
        return this.collection.search(this.query, {
            projection: this.options.projection,
            sort: this.sortSpec,
            limit: this.limitCount
        });
    }
}

class ElasticCollection {
    constructor(database, name) {
        this.database = database;
        this.name = name;
    }

    async createIndex() {
        return `${this.name}_index`;
    }

    async insertOne(document) {
        const doc = serialize({ ...document });
        if (this.name === 'users' && doc.username) {
            const existing = await this.findOne({ username: doc.username });
            if (existing) {
                const error = new Error('Duplicate key');
                error.code = 11000;
                throw error;
            }
        }
        const id = normalizeId(doc._id || new ObjectId());
        doc._id = id;
        await this.database.request('PUT', `/${this.database.indexName(this.name)}/_doc/${encodeURIComponent(id)}?refresh=true`, sourceWithoutId(doc));
        return { acknowledged: true, insertedId: id };
    }

    async findOne(query = {}, options = {}) {
        const id = normalizeId(query._id);
        if (id) {
            const response = await this.database.request('GET', `/${this.database.indexName(this.name)}/_doc/${encodeURIComponent(id)}`, null, { allow404: true });
            if (!response || response.found === false) return null;
            return applyProjection(this.database.fromHit(response), options.projection);
        }
        const docs = await this.search(query, { projection: options.projection, limit: 1 });
        return docs[0] || null;
    }

    find(query = {}, options = {}) {
        return new ElasticCursor(this, query, options);
    }

    async updateOne(filter, update, options = {}) {
        const existing = await this.findOne(filter);
        if (!existing && !options.upsert) {
            return { acknowledged: true, matchedCount: 0, modifiedCount: 0, upsertedId: null };
        }

        const baseId = normalizeId(filter && filter._id) || normalizeId(existing && existing._id) || normalizeId(new ObjectId());
        const next = existing ? { ...existing } : { _id: baseId };
        if (!existing && update.$setOnInsert) Object.assign(next, serialize(update.$setOnInsert));
        if (update.$set) {
            for (const [key, value] of Object.entries(serialize(update.$set))) setPath(next, key, value);
        }
        if (update.$unset) {
            for (const key of Object.keys(update.$unset)) unsetPath(next, key);
        }
        if (!update.$set && !update.$unset && !update.$setOnInsert) Object.assign(next, serialize(update));
        next._id = baseId;

        await this.database.request('PUT', `/${this.database.indexName(this.name)}/_doc/${encodeURIComponent(baseId)}?refresh=true`, sourceWithoutId(serialize(next)));
        return {
            acknowledged: true,
            matchedCount: existing ? 1 : 0,
            modifiedCount: existing ? 1 : 0,
            upsertedId: existing ? null : baseId
        };
    }

    async deleteOne(filter) {
        const doc = await this.findOne(filter);
        if (!doc) return { acknowledged: true, deletedCount: 0 };
        await this.database.request('DELETE', `/${this.database.indexName(this.name)}/_doc/${encodeURIComponent(normalizeId(doc._id))}?refresh=true`, null, { allow404: true });
        return { acknowledged: true, deletedCount: 1 };
    }

    async search(query, options = {}) {
        const body = {
            query: this.database.buildQuery(query),
            size: options.limit || 1000
        };
        if (options.sort) {
            body.sort = Object.entries(options.sort).map(([field, direction]) => ({
                [field]: { order: direction === -1 ? 'desc' : 'asc', unmapped_type: 'keyword' }
            }));
        }
        const response = await this.database.request('POST', `/${this.database.indexName(this.name)}/_search`, body);
        return (response.hits?.hits || []).map(hit => applyProjection(this.database.fromHit(hit), options.projection));
    }
}

class ElasticDatabase {
    constructor(config) {
        this.config = config;
        this.databaseName = config.indexPrefix;
    }

    collection(name) {
        return new ElasticCollection(this, name);
    }

    indexName(name) {
        return `${this.config.indexPrefix}-${name}`.toLowerCase().replace(/[^a-z0-9._-]/g, '-');
    }

    async command(command) {
        if (command && command.ping) {
            await this.ping();
            return { ok: 1 };
        }
        return { ok: 1 };
    }

    async ping() {
        await this.request('GET', '/');
    }

    async ensureSchema() {
        const mappings = {
            dynamic_templates: [
                { strings_as_keywords: { match_mapping_type: 'string', mapping: { type: 'keyword', ignore_above: 4096 } } }
            ],
            properties: {
                createdAt: { type: 'date', ignore_malformed: true },
                updatedAt: { type: 'date', ignore_malformed: true },
                checkedAt: { type: 'date', ignore_malformed: true },
                lastLoginAt: { type: 'date', ignore_malformed: true },
                migratedAt: { type: 'date', ignore_malformed: true }
            }
        };

        for (const collection of COLLECTIONS) {
            const index = this.indexName(collection);
            const exists = await this.request('HEAD', `/${index}`, null, { allow404: true, raw: true });
            if (exists.status !== 200) {
                await this.request('PUT', `/${index}`, { mappings });
            }
        }
        return { supported: true };
    }

    buildQuery(query = {}) {
        const entries = Object.entries(query || {}).filter(([, value]) => value !== undefined);
        if (entries.length === 0) return { match_all: {} };
        const filters = entries.map(([field, value]) => {
            if (field === '_id') return { ids: { values: [normalizeId(value)] } };
            return { term: { [field]: serialize(value) } };
        });
        return { bool: { filter: filters } };
    }

    fromHit(hit) {
        const source = hit._source || {};
        return { ...source, _id: source._id || hit._id };
    }

    headers() {
        const headers = { accept: 'application/json' };
        if (this.config.apiKey) {
            headers.authorization = `ApiKey ${this.config.apiKey}`;
        } else if (this.config.username) {
            headers.authorization = `Basic ${Buffer.from(`${this.config.username}:${this.config.password}`).toString('base64')}`;
        }
        return headers;
    }

    async request(method, path, body, options = {}) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.config.requestTimeoutMS);
        try {
            const response = await fetch(`${this.config.url}${path}`, {
                method,
                headers: body == null ? this.headers() : { ...this.headers(), 'content-type': 'application/json' },
                body: body == null ? undefined : JSON.stringify(body),
                signal: controller.signal
            });
            if (options.raw) return response;
            if (options.allow404 && response.status === 404) return null;
            const text = await response.text();
            const data = text ? JSON.parse(text) : {};
            if (!response.ok) {
                const reason = data.error?.reason || data.error?.type || response.statusText;
                throw new Error(`Elasticsearch ${response.status}: ${reason}`);
            }
            return data;
        } finally {
            clearTimeout(timeout);
        }
    }
}

module.exports = {
    ElasticDatabase,
    COLLECTIONS,
    normalizeId,
    getPath
};
