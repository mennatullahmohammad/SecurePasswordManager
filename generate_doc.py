from fpdf import FPDF
import textwrap

class PDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 11)
        self.set_fill_color(30, 60, 120)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, "Secure Password Manager - Module 4 Documentation", align="C", fill=True, new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

    def section_title(self, title):
        self.set_font("Helvetica", "B", 13)
        self.set_fill_color(220, 230, 245)
        self.set_text_color(20, 40, 100)
        self.cell(0, 8, title, fill=True, new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def subsection_title(self, title):
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(30, 70, 150)
        self.cell(0, 7, title, new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.ln(1)

    def body_text(self, text, indent=0):
        self.set_font("Helvetica", "", 10)
        self.set_x(self.l_margin + indent)
        self.multi_cell(0, 6, text)
        self.ln(1)

    def code_block(self, code):
        self.set_font("Courier", "", 9)
        self.set_fill_color(245, 245, 245)
        self.set_draw_color(200, 200, 200)
        lines = code.split("\n")
        x = self.l_margin
        w = self.w - self.l_margin - self.r_margin
        self.rect(x, self.get_y(), w, len(lines) * 5.2 + 4, style="DF")
        self.ln(2)
        for line in lines:
            self.set_x(x + 2)
            self.cell(0, 5.2, line)
            self.ln()
        self.ln(3)

    def param_table(self, headers, rows):
        self.set_font("Helvetica", "B", 9)
        col_w = [45, 35, 95]
        self.set_fill_color(180, 200, 230)
        self.set_text_color(0, 0, 0)
        for i, h in enumerate(headers):
            self.cell(col_w[i], 7, h, border=1, fill=True)
        self.ln()
        self.set_font("Helvetica", "", 9)
        fill = False
        for row in rows:
            self.set_fill_color(240, 245, 255) if fill else self.set_fill_color(255, 255, 255)
            for i, cell in enumerate(row):
                self.multi_cell(col_w[i], 6, cell, border=1, fill=True, new_x="RIGHT", new_y="LAST", max_line_height=6)
            self.ln()
            fill = not fill
        self.ln(3)


pdf = PDF()
pdf.set_auto_page_break(auto=True, margin=15)
pdf.add_page()

# -- Title Page --------------------------------------------------------------
pdf.ln(10)
pdf.set_font("Helvetica", "B", 20)
pdf.set_text_color(20, 40, 100)
pdf.cell(0, 12, "Module 4: Vault Transfer", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.set_font("Helvetica", "", 12)
pdf.set_text_color(80, 80, 80)
pdf.cell(0, 8, "Secure Password Manager Project", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.set_font("Helvetica", "", 10)
pdf.cell(0, 7, "Rana Elgharabawy  |  2026", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.set_text_color(0, 0, 0)
pdf.ln(10)

# -- Overview ----------------------------------------------------------------
pdf.section_title("1. Overview")
pdf.body_text(
    "Module 4 implements secure vault transfer between two users of the Secure Password Manager. "
    "It combines Diffie-Hellman (DH) key exchange, AES-GCM symmetric encryption, and ElGamal "
    "digital signatures (from Module 3) to allow one user (sender) to export their encrypted "
    "credential vault to another user (receiver) without ever exposing plaintext credentials or "
    "the master password over the transfer channel."
)
pdf.body_text("Key responsibilities of this module:")
for point in [
    "Perform DH key exchange to derive a shared session key.",
    "Re-encrypt the vault under the shared session key for transit.",
    "Sign the exported vault to guarantee authenticity and integrity.",
    "Verify the sender's signature on import before accepting credentials.",
    "Merge imported credentials into the receiver's vault, skipping duplicates.",
]:
    pdf.set_font("Helvetica", "", 10)
    pdf.set_x(pdf.l_margin + 5)
    pdf.cell(5, 6, chr(149))
    pdf.multi_cell(0, 6, point)
pdf.ln(3)

# -- Dependencies -------------------------------------------------------------
pdf.section_title("2. Dependencies")
pdf.param_table(
    ["Module / Library", "Source", "Purpose"],
    [
        ["module_2", "Internal", "encrypt_credentials, decrypt_credentials, add_credential"],
        ["module_3", "Internal", "sign, verify, hash_vault (ElGamal DSA)"],
        ["config", "Internal", "load_params, load_json (DH parameters)"],
        ["pycryptodome", "External", "AES-GCM cipher, secure random integer"],
        ["hashlib", "stdlib", "SHA-256 key derivation"],
        ["os, json, base64", "stdlib", "File I/O, serialisation, encoding"],
    ]
)

# -- Cryptographic Primitives -------------------------------------------------
pdf.section_title("3. Cryptographic Primitives")

pdf.subsection_title("3.1 Diffie-Hellman Key Exchange")
pdf.body_text(
    "The module reuses the DH parameters (prime q and generator alpha) already stored in each "
    "user's public key JSON file. The DH key exchange proceeds as follows:"
)
pdf.body_text("  1. Sender computes shared secret:  K = Y_receiver ^ x_sender  mod q", indent=5)
pdf.body_text("  2. Receiver computes shared secret: K = Y_sender  ^ x_receiver mod q", indent=5)
pdf.body_text("Both sides arrive at the same K without transmitting private keys.", indent=5)
pdf.ln(2)

pdf.subsection_title("3.2 Session Key Derivation")
pdf.body_text(
    "The raw DH shared integer K is hashed with SHA-256 to produce a 32-byte (256-bit) AES key:\n"
    "    session_key = SHA-256( str(K).encode() )"
)

pdf.subsection_title("3.3 AES-GCM Encryption")
pdf.body_text(
    "Credentials are re-encrypted using AES-256-GCM, which provides both confidentiality and "
    "authenticated integrity. The wire format (base64-encoded) bundles:"
)
for item in ["Bytes  0-15 : random nonce (16 bytes)", "Bytes 16-31 : GCM authentication tag (16 bytes)", "Bytes 32+   : ciphertext"]:
    pdf.set_font("Courier", "", 9)
    pdf.set_x(pdf.l_margin + 5)
    pdf.cell(0, 6, item, new_x="LMARGIN", new_y="NEXT")
pdf.ln(2)

pdf.subsection_title("3.4 ElGamal Digital Signature")
pdf.body_text(
    "Before export, the module signs the re-encrypted vault blob using the sender's ElGamal "
    "private key (via module_3.sign). On import, the receiver verifies the signature with the "
    "sender's public key before decrypting anything, ensuring the transfer file was not tampered "
    "with in transit."
)
pdf.ln(2)

# -- Function Reference --------------------------------------------------------
pdf.section_title("4. Function Reference")

functions = [
    {
        "sig": "select_keys(q, alpha) -> (int, int)",
        "desc": (
            "Generates a fresh DH key pair within the group (q, alpha). Picks a random private key "
            "x in [2, q-2] and computes public key y = alpha^x mod q."
        ),
        "params": [
            ("q", "int", "Safe prime - the DH group order"),
            ("alpha", "int", "Generator of the DH group"),
        ],
        "returns": "Tuple (private_key x, public_key y)",
        "note": None,
    },
    {
        "sig": "compute_key(otherPubKey, myPrivKey, q) -> int",
        "desc": "Computes the DH shared secret: K = otherPubKey ^ myPrivKey mod q.",
        "params": [
            ("otherPubKey", "int", "Counterpart's DH public key (y)"),
            ("myPrivKey",   "int", "Own DH private key (x)"),
            ("q",           "int", "DH group prime"),
        ],
        "returns": "Shared secret integer K",
        "note": None,
    },
    {
        "sig": "hash_key(key) -> bytes",
        "desc": "Derives a 32-byte AES key from a DH shared secret integer using SHA-256.",
        "params": [("key", "int", "DH shared secret integer K")],
        "returns": "32-byte bytes object suitable for AES-256",
        "note": None,
    },
    {
        "sig": "AES_encrypt(plaintext: bytes, key: bytes) -> str",
        "desc": (
            "Encrypts plaintext with AES-256-GCM using a freshly generated nonce. "
            "Returns a base64-encoded string containing nonce || tag || ciphertext."
        ),
        "params": [
            ("plaintext", "bytes", "Data to encrypt"),
            ("key",       "bytes", "32-byte AES session key"),
        ],
        "returns": "Base64 string: nonce(16) + tag(16) + ciphertext",
        "note": None,
    },
    {
        "sig": "AES_decrypt(bundle: str, key: bytes) -> bytes",
        "desc": "Decrypts a bundle produced by AES_encrypt. Raises ValueError if authentication fails.",
        "params": [
            ("bundle", "str",   "Base64 string from AES_encrypt"),
            ("key",    "bytes", "32-byte AES session key"),
        ],
        "returns": "Decrypted plaintext bytes",
        "note": "Raises ValueError on tag mismatch (tampering detected).",
    },
    {
        "sig": "export_vault(sender, receiver, master_password)",
        "desc": (
            "High-level export workflow. Loads the sender's vault, verifies its integrity, "
            "decrypts it with the master password, re-encrypts it under the DH session key, "
            "signs the export, and writes a JSON transfer file to the transfers/ directory."
        ),
        "params": [
            ("sender",          "str", "Username of the exporting user"),
            ("receiver",        "str", "Username of the target user"),
            ("master_password", "str", "Sender's vault master password"),
        ],
        "returns": "None - writes transfers/<sender>_to_<receiver>.json",
        "note": "Raises FileNotFoundError if keys/vault are missing; PermissionError if signature invalid.",
    },
    {
        "sig": "import_vault(receiver, sender, master_password)",
        "desc": (
            "High-level import workflow. Reads the transfer file, verifies the sender's "
            "ElGamal signature, decrypts the payload with the DH session key, and merges "
            "credentials into the receiver's vault (skipping duplicates). Deletes the "
            "transfer file after successful import."
        ),
        "params": [
            ("receiver",        "str", "Username of the importing user"),
            ("sender",          "str", "Username of the original exporter"),
            ("master_password", "str", "Receiver's own master password"),
        ],
        "returns": "None - updates receiver's vault and prints import summary",
        "note": "Raises PermissionError if signature verification fails; FileNotFoundError if transfer file missing.",
    },
]

for fn in functions:
    pdf.subsection_title(fn["sig"])
    pdf.body_text(fn["desc"])
    if fn["params"]:
        pdf.set_font("Helvetica", "B", 9)
        pdf.body_text("Parameters:")
        pdf.param_table(
            ["Parameter", "Type", "Description"],
            [[p[0], p[1], p[2]] for p in fn["params"]]
        )
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_x(pdf.l_margin)
    pdf.cell(25, 6, "Returns:")
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(0, 6, fn["returns"])
    if fn["note"]:
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 6, f"Note: {fn['note']}")
    pdf.ln(3)

# -- Security Design -----------------------------------------------------------
pdf.section_title("5. Security Design")

rows = [
    ("Confidentiality in transit",
     "Vault re-encrypted with AES-256-GCM under ephemeral DH session key; master password never leaves the local machine."),
    ("Integrity / Authenticity",
     "ElGamal signature over the exported blob; receiver verifies before decrypting."),
    ("Key freshness",
     "AES_encrypt generates a fresh random nonce per call, preventing nonce reuse."),
    ("Tamper detection",
     "AES-GCM authentication tag rejects modified ciphertext with ValueError."),
    ("No master-password exposure",
     "The master password is used only to decrypt locally; the session key (DH-derived) is used for the export bundle."),
    ("Transfer file cleanup",
     "Transfer file deleted after successful import to limit exposure window."),
]

for threat, mitigation in rows:
    pdf.set_font("Helvetica", "B", 10)
    pdf.body_text(threat + ":")
    pdf.set_font("Helvetica", "", 10)
    pdf.body_text(mitigation, indent=8)

# -- Data Flow -----------------------------------------------------------------
pdf.section_title("6. Data Flow Diagram (Export)")
pdf.set_font("Courier", "", 9)
flow = [
    "Sender                                     Receiver",
    "------                                     --------",
    "Load vault (JSON)                          (waiting)",
    "  v",
    "Verify own vault signature  [module_3]",
    "  v",
    "Decrypt vault with master_password  [module_2]",
    "  v",
    "Compute DH session key:                    Compute DH session key:",
    "  K = Y_receiver ^ x_sender mod q           K = Y_sender ^ x_receiver mod q",
    "  session_key = SHA-256(K)                   session_key = SHA-256(K)",
    "  v",
    "Re-encrypt vault with session_key  [AES-GCM]",
    "  v",
    "Sign encrypted_export with x_sender  [module_3]",
    "  v",
    "Write  transfers/sender_to_receiver.json",
    "                                             v",
    "                                           Read transfer file",
    "                                             v",
    "                                           Verify signature  [module_3]",
    "                                             v",
    "                                           Decrypt with session_key  [AES-GCM]",
    "                                             v",
    "                                           Merge into own vault  [module_2]",
    "                                             v",
    "                                           Delete transfer file",
]
for line in flow:
    pdf.set_x(pdf.l_margin + 2)
    pdf.cell(0, 5, line, new_x="LMARGIN", new_y="NEXT")
pdf.ln(4)

# -- Transfer File Format ------------------------------------------------------
pdf.section_title("7. Transfer File Format")
pdf.body_text(
    "Export writes a JSON file at transfers/<sender>_to_<receiver>.json with the following structure:"
)
pdf.code_block("""{
  "sender":         "<sender_username>",
  "recipient":      "<receiver_username>",
  "encrypted_vault": "<base64: nonce||tag||ciphertext>",
  "signature": {
    "r": "<ElGamal r component>",
    "s": "<ElGamal s component>"
  }
}""")

# -- Test Suite ----------------------------------------------------------------
pdf.add_page()
pdf.section_title("8. Test Suite - test_module_4.py")
pdf.body_text(
    "The test file is an integration script that exercises the full export -> import pipeline "
    "end-to-end using two test users: alice (sender) and bob (receiver). It is run from the "
    "modules/ directory and prints results at each step."
)

steps = [
    ("Step 1 - Initialize vaults",
     "module_2.initialize_vault is called for both alice and bob. This creates their DH key pairs "
     "in keys/ and empty encrypted vaults in vaults/.",
     'module_2.initialize_vault("alice", "alicepass")\nmodule_2.initialize_vault("bob",   "bobpass")'),

    ("Step 2 - Populate alice's vault",
     "Two credentials are added to alice's vault: github.com and netflix.com. Each add_credential "
     "call re-signs the vault to maintain integrity.",
     'module_2.add_credential("alice", "alicepass", "github.com",  "alice@email.com", "gh_secret")\n'
     'module_2.add_credential("alice", "alicepass", "netflix.com", "alice@email.com", "nf_secret")'),

    ("Step 3 - Verify alice's vault contents",
     "get_credentials is called to display alice's credentials before export, confirming the vault "
     "has the expected entries.",
     'for c in module_2.get_credentials("alice", "alicepass"):\n    print(c["site"], c["username"], c["password"])'),

    ("Step 4 - Export alice's vault to bob",
     "export_vault performs DH key exchange, re-encrypts alice's vault under the session key, "
     "signs it with alice's private key, and writes the transfer file.",
     'module_4.export_vault("alice", "bob", "alicepass")'),

    ("Step 5 - Bob imports the vault",
     "import_vault verifies alice's signature, decrypts using the DH session key, and merges all "
     "credentials into bob's vault. The transfer file is deleted on success.",
     'module_4.import_vault("bob", "alice", "bobpass")'),

    ("Step 6 - Verify bob's vault contents",
     "get_credentials is called on bob's vault to confirm that github.com and netflix.com "
     "credentials were imported correctly.",
     'for c in module_2.get_credentials("bob", "bobpass"):\n    print(c["site"], c["username"], c["password"])'),
]

for title, desc, code in steps:
    pdf.subsection_title(title)
    pdf.body_text(desc)
    pdf.code_block(code)

# -- Expected Output -----------------------------------------------------------
pdf.section_title("9. Expected Test Output")
pdf.code_block(
"""=== Step 1: Initialize vaults ===
Vault initialized for 'alice'
Vault initialized for 'bob'

=== Step 2: Add credentials to alice's vault ===
Credential for 'github.com' added successfully.
Credential for 'netflix.com' added successfully.

=== Step 3: alice's vault before export ===
  github.com  | alice@email.com | gh_secret
  netflix.com | alice@email.com | nf_secret

=== Step 4: Export alice's vault to bob ===
Vault exported successfully to 'bob'.
Transfer file: transfers/alice_to_bob.json

=== Step 5: Bob imports the vault ===
Import complete: 2 credential(s) imported, 0 skipped (already exist).
Transfer file cleaned up.

=== Step 6: Bob's vault after import ===
  github.com  | alice@email.com | gh_secret
  netflix.com | alice@email.com | nf_secret"""
)

# -- Error Cases ---------------------------------------------------------------
pdf.section_title("10. Error Handling")
pdf.param_table(
    ["Condition", "Exception", "Where Raised"],
    [
        ("Sender keys not found",          "FileNotFoundError", "export_vault"),
        ("Receiver keys not found",        "FileNotFoundError", "export_vault"),
        ("Sender vault not found",         "FileNotFoundError", "export_vault"),
        ("Vault signature missing/invalid","PermissionError",   "export_vault"),
        ("Transfer file not found",        "FileNotFoundError", "import_vault"),
        ("Transfer signature invalid",     "PermissionError",   "import_vault"),
        ("Receiver keys not found",        "FileNotFoundError", "import_vault"),
        ("Receiver vault not found",       "FileNotFoundError", "import_vault"),
        ("AES tag mismatch (tampered)",    "ValueError",        "AES_decrypt"),
    ]
)

out = "module_4_documentation.pdf"
pdf.output(out)
print(f"PDF generated: {out}")
