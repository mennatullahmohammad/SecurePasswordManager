# test_module2.py

import module_2
import json

USERNAME = "ali"
MASTER_PASSWORD = "mypass123"

print("\n========== TEST 1: Initialize Vault ==========")
module_2.initialize_vault(USERNAME, MASTER_PASSWORD)

print("\n========== TEST 2: Add Credentials ==========")
module_2.add_credential(USERNAME, MASTER_PASSWORD, "google.com", "ali@gmail.com", "hunter2")
module_2.add_credential(USERNAME, MASTER_PASSWORD, "github.com", "ali_dev", "secret456")
module_2.add_credential(USERNAME, MASTER_PASSWORD, "netflix.com", "ali@gmail.com", "movie789")

print("\n========== TEST 3: Get Specific Credential ==========")
result = module_2.get_credentials(USERNAME, MASTER_PASSWORD, "google.com")
print(f"Found: {result}")

print("\n========== TEST 4: Get All Credentials ==========")
all_creds = module_2.get_credentials(USERNAME, MASTER_PASSWORD)
print(f"All credentials: {all_creds}")

print("\n========== TEST 5: Update Username Only ==========")
module_2.update_credential(USERNAME, MASTER_PASSWORD, "google.com", new_username="newemail@gmail.com")
result = module_2.get_credentials(USERNAME, MASTER_PASSWORD, "google.com")
print(f"After username update: {result}")

print("\n========== TEST 6: Update Password Only ==========")
module_2.update_credential(USERNAME, MASTER_PASSWORD, "google.com", new_password="newpass999")
result = module_2.get_credentials(USERNAME, MASTER_PASSWORD, "google.com")
print(f"After password update: {result}")

print("\n========== TEST 7: Update Both Username and Password ==========")
module_2.update_credential(USERNAME, MASTER_PASSWORD, "github.com", new_username="ali_updated", new_password="updatedpass123")
result = module_2.get_credentials(USERNAME, MASTER_PASSWORD, "github.com")
print(f"After full update: {result}")

print("\n========== TEST 8: Delete Credential ==========")
module_2.delete_credential(USERNAME, MASTER_PASSWORD, "netflix.com")
all_creds = module_2.get_credentials(USERNAME, MASTER_PASSWORD)
print(f"After delete (netflix should be gone): {all_creds}")

print("\n========== TEST 9: Wrong Master Password ==========")
try:
    module_2.get_credentials(USERNAME, "wrongpassword", "google.com")
except ValueError as e:
    print(f"Caught expected error: {e}")

print("\n========== TEST 10: Duplicate Entry ==========")
try:
    module_2.add_credential(USERNAME, MASTER_PASSWORD, "google.com", "someone", "somepass")
except ValueError as e:
    print(f"Caught expected error: {e}")

print("\n========== TEST 11: Get Non-Existent Site ==========")
try:
    module_2.get_credentials(USERNAME, MASTER_PASSWORD, "twitter.com")
except ValueError as e:
    print(f"Caught expected error: {e}")

print("\n========== TEST 12: Update Non-Existent Site ==========")
try:
    module_2.update_credential(USERNAME, MASTER_PASSWORD, "twitter.com", new_password="pass")
except ValueError as e:
    print(f"Caught expected error: {e}")

print("\n========== TEST 13: Delete Non-Existent Site ==========")
try:
    module_2.delete_credential(USERNAME, MASTER_PASSWORD, "twitter.com")
except ValueError as e:
    print(f"Caught expected error: {e}")

print("\n========== TEST 14: Tamper Detection ==========")
vault_path = f"vaults/{USERNAME}_vault.json"
with open(vault_path, "r") as f:
    vault = json.load(f)

original = vault["encrypted_vault"]
vault["encrypted_vault"] = original[:-5] + "XXXXX"

with open(vault_path, "w") as f:
    json.dump(vault, f)

try:
    module_2.get_credentials(USERNAME, MASTER_PASSWORD, "google.com")
except PermissionError as e:
    print(f"Caught expected error: {e}")

print("\n========== ALL TESTS DONE ==========")