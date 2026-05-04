import module_2
import module_4

# ── Setup ──────────────────────────────────────────────────────────────────────
# Two users: alice (sender) and bob (receiver)
# Run this from the modules/ directory

print("=== Step 1: Initialize vaults ===")
module_2.initialize_vault("alice", "alicepass")
module_2.initialize_vault("bob",   "bobpass")

print("\n=== Step 2: Add credentials to alice's vault ===")
module_2.add_credential("alice", "alicepass", "github.com",  "alice@email.com", "gh_secret")
module_2.add_credential("alice", "alicepass", "netflix.com", "alice@email.com", "nf_secret")

print("\n=== Step 3: alice's vault before export ===")
for c in module_2.get_credentials("alice", "alicepass"):
    print(f"  {c['site']} | {c['username']} | {c['password']}")

print("\n=== Step 4: Export alice's vault to bob ===")
module_4.export_vault("alice", "bob", "alicepass")

print("\n=== Step 5: Bob imports the vault ===")
module_4.import_vault("bob", "alice", "bobpass")

print("\n=== Step 6: Bob's vault after import ===")
for c in module_2.get_credentials("bob", "bobpass"):
    print(f"  {c['site']} | {c['username']} | {c['password']}")
