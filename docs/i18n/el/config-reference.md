# Οδηγός Ρυθμίσεων ZeroClaw (config.toml)

Αυτός ο οδηγός εξηγεί τις πιο σημαντικές ρυθμίσεις που μπορείτε να κάνετε στο αρχείο `config.toml`.

Τελευταίος έλεγχος: **19 Φεβρουαρίου 2026**.

## Πού βρίσκεται το αρχείο ρυθμίσεων;

Το ZeroClaw ψάχνει για τις ρυθμίσεις με την εξής σειρά:
1. Στη διαδρομή που ορίζει η μεταβλητή `ZEROCLAW_WORKSPACE`.
2. Στο αρχείο `~/.zeroclaw/config.toml` (αυτή είναι η συνηθισμένη θέση).

## Βασικές Ρυθμίσεις (Core)

| Ρύθμιση | Τι ορίζει |
|---|---|
| `default_provider` | Ποιον πάροχο AI χρησιμοποιείτε (π.χ. `openai`, `ollama`). |
| `default_model` | Ποιο συγκεκριμένο μοντέλο AI χρησιμοποιείτε (π.χ. `gpt-4o`). |
| `default_temperature` | Πόσο "δημιουργική" θα είναι η AI (τιμή από 0 έως 2). |

## 1. Συμπεριφορά της AI (Agent)

- `max_tool_iterations`: Πόσες φορές μπορεί η AI να χρησιμοποιήσει εργαλεία για να απαντήσει σε 1 μήνυμα (προεπιλογή: 10).
- `max_history_messages`: Πόσα προηγούμενα μηνύματα θυμάται η AI στη συνομιλία (προεπιλογή: 50).

## 2. Αυτονομία και Ασφάλεια (Autonomy)

Εδώ ρυθμίζετε πόση ελευθερία έχει η AI να κάνει αλλαγές στον υπολογιστή σας.

- `level`: 
    - `read_only`: Μπορεί μόνο να διαβάζει αρχεία.
    - `supervised`: Χρειάζεται την έγκρισή σας για σημαντικές ενέργειες (προεπιλογή).
    - `full`: Μπορεί να τρέχει εντολές ελεύθερα (προσοχή!).
- `allowed_commands`: Λίστα με τις εντολές που επιτρέπεται να τρέχει η AI.
- `command_context_rules`: Πιο λεπτοί allow/deny κανόνες ανά εντολή με περιορισμούς domain/path.
- `unrestricted_commands`: Break-glass λευκή λίστα που παρακάμπτει όλα τα shell policy gates για τις εντολές που ταιριάζουν.
- `shell_env_passthrough`: Επιπλέον ονόματα μεταβλητών περιβάλλοντος που επιτρέπεται να περάσουν σε shell subprocesses.
- `forbidden_paths`: Φάκελοι που η AI **δεν** επιτρέπεται να αγγίξει (π.χ. `/etc`).
- `allowed_roots`: Επιπλέον roots εκτός workspace που επιτρέπονται ρητά.
- `max_actions_per_hour`: Προεπιλογή `100`.
- `max_cost_per_day_cents`: Προεπιλογή `1000`.
- `allow_unsafe_shell_structures`: Προεπιλογή `false`· επιτρέπει redirection/substitution/background operators μόνο με explicit opt-in.
- `auto_approve`: Προεπιλογή `["file_read","memory_recall"]`.
- `non_cli_excluded_tools`: Ενσωματωμένη λίστα εργαλείων που κρύβονται από non-CLI κανάλια.

Σημειώσεις:

- Για path policy στο `[autonomy]` και για allow rules στο `command_context_rules`, κερδίζει το πιο συγκεκριμένο matching prefix ανάμεσα σε allow και deny.
- Το `allowed_commands` ανοίγει μόνο το allowlist ονομάτων/μονοπατιών εντολών. Τα υπόλοιπα shell guardrails παραμένουν ενεργά.
- Το `unrestricted_commands` είναι το πραγματικό hard whitelist: παρακάμπτει `allowed_commands`, `command_context_rules`, path guards, shell-structure guards, read-only/autonomy prechecks και approval/risk gates. Κρατήστε το πολύ στενό.

## 3. Μνήμη (Memory)

Πώς αποθηκεύει η AI τις πληροφορίες που της δίνετε.
- `backend`: Μπορεί να είναι `sqlite` (βάση δεδομένων), `markdown` (απλά αρχεία κειμένου) ή `none` (καμία μνήμη).

## 4. Κανάλια Επικοινωνίας (Channels)

Κάθε κανάλι (Telegram, Discord κ.λπ.) έχει τη δική του ενότητα στο αρχείο.

Παράδειγμα για το **Telegram**:
```toml
[channels_config.telegram]
bot_token = "το-κλειδί-σας"
allowed_users = ["το-όνομά-σας"] # Ποιοι επιτρέπεται να μιλάνε στο bot
```

## 5. Έλεγχος Κόστους (Cost)

Αν χρησιμοποιείτε πληρωμένες υπηρεσίες AI, μπορείτε να βάλετε όρια.
- `daily_limit_usd`: Μέγιστο ποσό ανά ημέρα (π.χ. 10.00 δολάρια).
- `monthly_limit_usd`: Μέγιστο ποσό ανά μήνα.

## 6. Εικόνες (Multimodal)

Ρυθμίσεις για το πώς η AI βλέπει εικόνες.
- `max_images`: Μέγιστος αριθμός εικόνων ανά μήνυμα.
- `allow_remote_fetch`: Αν επιτρέπεται στην AI να κατεβάζει εικόνες από το ίντερνετ μέσω συνδέσμων (links).

---

## Συμβουλές

- Αν αλλάξετε το αρχείο `config.toml`, πρέπει να κάνετε επανεκκίνηση το ZeroClaw για να δει τις αλλαγές.
- Χρησιμοποιήστε την εντολή `zeroclaw doctor` για να βεβαιωθείτε ότι οι ρυθμίσεις σας είναι σωστές.
- Μην μοιράζεστε ποτέ το αρχείο `config.toml` με άλλους, καθώς περιέχει τα μυστικά κλειδιά σας (tokens).
