# main.py

import sys
import os
import argparse
import module_2



def print_header():
    print("""
╔══════════════════════════════════════╗
║      Secure Password Manager         ║
║   CMPS426 - Cairo University         ║
╚══════════════════════════════════════╝
""")


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_menu():
    print("""
--------- MAIN MENU ---------
1. Initialize vault
2. Add credential
3. Get credential
4. Get all credentials
5. Update credential
6. Delete credential
7. Export vault (Module 4)
8. Import vault (Module 4)
9. Switch user
0. Exit
-----------------------------""")


def get_username():
    while True:
        username = input("Enter your username: ").strip().lower()
        if username:
            return username
        print("Username cannot be empty.")


def get_master_password():
    while True:
        password = input("Enter master password: ").strip()
        if password:
            return password
        print("Master password cannot be empty.")


def handle_initialize(username):
    master = get_master_password()
    try:
        module_2.initialize_vault(username, master)
    except Exception as e:
        print(f"Error: {e}")


def handle_add(username):
    master = get_master_password()
    site = input("Enter site (e.g. google.com): ").strip()
    if not site:
        print("Site cannot be empty.")
        return
    site_username = input("Enter username for that site: ").strip()
    site_password = input("Enter password for that site: ").strip()
    if not site_username or not site_password:
        print("Username and password cannot be empty.")
        return
    try:
        module_2.add_credential(username, master, site, site_username, site_password)
    except PermissionError as e:
        print(f"Security Alert: {e}")
    except ValueError as e:
        print(f"Error: {e}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Hint: Initialize your vault first.")


def handle_get(username):
    master = get_master_password()
    site = input("Enter site to retrieve: ").strip()
    if not site:
        print("Site cannot be empty.")
        return
    try:
        result = module_2.get_credentials(username, master, site)
        if result:
            print(f"\n--- Credentials for {site} ---")
            print(f"  Site     : {result[0]['site']}")
            print(f"  Username : {result[0]['username']}")
            print(f"  Password : {result[0]['password']}")
            print("------------------------------")
    except PermissionError as e:
        print(f"Security Alert: {e}")
    except ValueError as e:
        print(f"Error: {e}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Hint: Initialize your vault first.")


def handle_get_all(username):
    master = get_master_password()
    try:
        results = module_2.get_credentials(username, master)
        if not results:
            print("Vault is empty. No credentials stored yet.")
            return
        print(f"\nFound {len(results)} credential(s):\n")
        for i, c in enumerate(results, 1):
            print(f"  [{i}] Site     : {c['site']}")
            print(f"      Username : {c['username']}")
            print(f"      Password : {c['password']}")
            print()
    except PermissionError as e:
        print(f"Security Alert: {e}")
    except ValueError as e:
        print(f"Error: {e}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Hint: Initialize your vault first.")


def handle_update(username):
    master = get_master_password()
    site = input("Enter site to update: ").strip()
    if not site:
        print("Site cannot be empty.")
        return
    print("Leave blank to keep current value.")
    new_username = input("New username (or press Enter to skip): ").strip()
    new_password = input("New password (or press Enter to skip): ").strip()
    if not new_username and not new_password:
        print("Nothing to update.")
        return
    try:
        module_2.update_credential(
            username, master, site,
            new_username=new_username if new_username else None,
            new_password=new_password if new_password else None
        )
    except PermissionError as e:
        print(f"Security Alert: {e}")
    except ValueError as e:
        print(f"Error: {e}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Hint: Initialize your vault first.")


def handle_delete(username):
    master = get_master_password()
    site = input("Enter site to delete: ").strip()
    if not site:
        print("Site cannot be empty.")
        return
    confirm = input(f"Are you sure you want to delete '{site}'? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Deletion cancelled.")
        return
    try:
        module_2.delete_credential(username, master, site)
    except PermissionError as e:
        print(f"Security Alert: {e}")
    except ValueError as e:
        print(f"Error: {e}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Hint: Initialize your vault first.")


def handle_export(username):
    try:
        import module_4
        recipient = input("Enter recipient username: ").strip().lower()
        if not recipient:
            print("Recipient username cannot be empty.")
            return
        master = get_master_password()
        module_4.export_vault(username, recipient, master)
    except ImportError:
        print("Module 4 is not available yet.")


def handle_import(username):
    try:
        import module_4
        sender = input("Enter sender username: ").strip().lower()
        if not sender:
            print("Sender username cannot be empty.")
            return
        master = get_master_password()
        module_4.import_vault(username, sender, master)
    except ImportError:
        print("Module 4 is not available yet.")


# ─── Argument Mode ────────────────────────────────────────────────────────────

def run_with_args(args):
    """
    Handles all argument-based commands directly without the interactive menu.
    """

    if args.command == "init":
        # python main.py --user ali init --master mypass123
        module_2.initialize_vault(args.user, args.master)

    elif args.command == "add":
        # python main.py --user ali add --master mypass123 --site google.com --siteuser ali@gmail.com --sitepass hunter2
        module_2.add_credential(
            args.user, args.master,
            args.site, args.siteuser, args.sitepass
        )

    elif args.command == "get":
        # python main.py --user ali get --master mypass123 --site google.com
        result = module_2.get_credentials(args.user, args.master, args.site)
        if result:
            print(f"\n--- Credentials for {args.site} ---")
            print(f"  Site     : {result[0]['site']}")
            print(f"  Username : {result[0]['username']}")
            print(f"  Password : {result[0]['password']}")
            print("------------------------------")

    elif args.command == "getall":
        # python main.py --user ali getall --master mypass123
        results = module_2.get_credentials(args.user, args.master)
        if not results:
            print("Vault is empty.")
            return
        print(f"\nFound {len(results)} credential(s):\n")
        for i, c in enumerate(results, 1):
            print(f"  [{i}] Site     : {c['site']}")
            print(f"      Username : {c['username']}")
            print(f"      Password : {c['password']}")
            print()

    elif args.command == "update":
        # python main.py --user ali update --master mypass123 --site google.com --siteuser newuser --sitepass newpass
        module_2.update_credential(
            args.user, args.master, args.site,
            new_username=args.siteuser if args.siteuser else None,
            new_password=args.sitepass if args.sitepass else None
        )

    elif args.command == "delete":
        # python main.py --user ali delete --master mypass123 --site google.com
        module_2.delete_credential(args.user, args.master, args.site)


# ─── Interactive Menu Mode ────────────────────────────────────────────────────

def run_interactive():
    clear()
    print_header()

    username = get_username()
    print(f"\nLogged in as: {username}")

    while True:
        print_menu()
        choice = input("Choose an option: ").strip()

        if choice == "1":
            handle_initialize(username)
        elif choice == "2":
            handle_add(username)
        elif choice == "3":
            handle_get(username)
        elif choice == "4":
            handle_get_all(username)
        elif choice == "5":
            handle_update(username)
        elif choice == "6":
            handle_delete(username)
        elif choice == "7":
            handle_export(username)
        elif choice == "8":
            handle_import(username)
        elif choice == "9":
            clear()
            print_header()
            username = get_username()
            print(f"\nSwitched to user: {username}")
        elif choice == "0":
            print("\nGoodbye.")
            sys.exit(0)
        else:
            print("Invalid option. Please choose 0-9.")

        input("\nPress Enter to continue...")
        clear()
        print_header()
        print(f"Logged in as: {username}")


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Secure Password Manager - CMPS426"
    )

    # If no arguments given → run interactive menu
    if len(sys.argv) == 1:
        run_interactive()
        return

    # Global argument: --user
    parser.add_argument("--user", required=True, help="Your username")

    subparsers = parser.add_subparsers(dest="command")

    # init
    init_parser = subparsers.add_parser("init", help="Initialize vault")
    init_parser.add_argument("--master", required=True, help="Master password")

    # add
    add_parser = subparsers.add_parser("add", help="Add a credential")
    add_parser.add_argument("--master",   required=True, help="Master password")
    add_parser.add_argument("--site",     required=True, help="Site name")
    add_parser.add_argument("--siteuser", required=True, help="Username for the site")
    add_parser.add_argument("--sitepass", required=True, help="Password for the site")

    # get
    get_parser = subparsers.add_parser("get", help="Get a credential")
    get_parser.add_argument("--master", required=True, help="Master password")
    get_parser.add_argument("--site",   required=True, help="Site name")

    # getall
    getall_parser = subparsers.add_parser("getall", help="Get all credentials")
    getall_parser.add_argument("--master", required=True, help="Master password")

    # update
    update_parser = subparsers.add_parser("update", help="Update a credential")
    update_parser.add_argument("--master",   required=True,  help="Master password")
    update_parser.add_argument("--site",     required=True,  help="Site name")
    update_parser.add_argument("--siteuser", required=False, help="New username (optional)")
    update_parser.add_argument("--sitepass", required=False, help="New password (optional)")

    # delete
    delete_parser = subparsers.add_parser("delete", help="Delete a credential")
    delete_parser.add_argument("--master", required=True, help="Master password")
    delete_parser.add_argument("--site",   required=True, help="Site name")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    try:
        run_with_args(args)
    except PermissionError as e:
        print(f"Security Alert: {e}")
    except ValueError as e:
        print(f"Error: {e}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Hint: Initialize your vault first with: python main.py --user <name> init --master <password>")


if __name__ == "__main__":
    main()