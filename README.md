# loginPanelCheckers

## Database

The Render deployment uses MongoDB by default. Configure these env values in Render:

```env
DB_PROVIDER=mongodb
MONGODB_URI=mongodb+srv://paymentmanger.gvaavzc.mongodb.net/?retryWrites=true&w=majority&authSource=admin&appName=paymentmanger
MONGODB_USERNAME=...
MONGODB_PASSWORD=...
MONGODB_DB_NAME=mydb
```

Elasticsearch remains available by setting:

```env
DB_PROVIDER=elasticsearch
ELASTICSEARCH_URL=https://your-elastic-host:9200
ELASTICSEARCH_API_KEY=...
ELASTICSEARCH_INDEX_PREFIX=loginpanelchecker
```

Elastic basic auth is also supported with `ELASTICSEARCH_USERNAME` and `ELASTICSEARCH_PASSWORD`.

## Login checker isolation

Each login attempt runs in a separate browser context. The runner clears browser state, adds short-lived synthetic trace cookies (`lpc_trace`, `lpc_attempt`) for reporting, and records URL, title, visible form state, error messages, MFA signals, and new auth/session cookie names.

Checks are restricted to admin-configured allowed hosts. Do not run credential lists against systems you do not own or do not have explicit authorization to test.
