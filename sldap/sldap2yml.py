#!venv/bin/python3
import re
import sys
import os # Required for creating directories and joining paths
import ldap # New import for LDAP operations
import ldap.filter # Useful for LDAP filter escaping, though not strictly used in this version
import time

# Define which epoch-based fields should have age calculated
epoch_variables_calculate_age = [
    "phpgwLastPasswdChange",  # example: epoch in seconds
]

def parse_ldap_entries_and_extract_attributes(ldap_entries, attributes_to_extract):
    """
    Parses LDAP entries obtained directly from an LDAP server and extracts specified attributes.

    It iterates through the LDAP entries (which are tuples of DN and attribute dictionary),
    collects all attributes for each user (identified by 'uid'), and then organizes this data
    by the specified attributes. If an attribute is missing for a user, an empty string
    is used as its value in the output.

    Args:
        ldap_entries (list): A list of tuples, where each tuple is (dn, attributes_dict).
                             attributes_dict contains byte string values.
        attributes_to_extract (list): A list of attribute names (strings) to extract.

    Returns:
        dict: A dictionary where keys are the requested attribute names and values are
              dictionaries. Each inner dictionary maps a 'uid' (from the LDAP server)
              to its corresponding extracted attribute value. If an attribute is not
              present for a user, its value will be an empty string.
    """
    all_users_attributes = {}  # Stores {uid: {attr1: val1, attr2: val2, ...}} for all users

    for dn, attrs in ldap_entries:
        uid = None
        current_entry_attributes = {} # Temporarily stores attributes for the current LDAP entry

        # Iterate through the attributes for the current LDAP entry
        for key, values in attrs.items():
            decoded_key = key
            decoded_value = "" # Default empty string

            try:
                # Safely decode the attribute key
                if isinstance(key, bytes):
                    decoded_key = key.decode('utf-8')
                
                # Safely decode the attribute value.
                # Assuming attributes are single-valued (values[0]).
                # If multi-valued, you might need to handle the list of values differently.
                if values and isinstance(values[0], bytes):
                    decoded_value = values[0].decode('utf-8')
                elif values: # If it's not bytes, assume it's already a string or another type
                    decoded_value = str(values[0]) # Convert to string to be safe
                
                current_entry_attributes[decoded_key] = decoded_value

                # Identify the UID for the current entry
                if decoded_key.lower() == 'uid':
                    uid = decoded_value

            except UnicodeDecodeError as e:
                print(f"Warning: Could not decode attribute '{key}' for DN '{dn}'. Error: {e}. Skipping this attribute.")
                continue # Skip to the next attribute for this entry
            except Exception as e:
                print(f"Warning: An unexpected error occurred while processing attribute '{key}' for DN '{dn}'. Error: {e}. Skipping this attribute.")
                continue # Skip to the next attribute for this entry


        # If a UID was found for this entry, store its attributes
        if uid:
            all_users_attributes[uid] = current_entry_attributes

    # Now, organize the extracted data specifically for the requested attributes.
    # This ensures that all requested attributes are present for every user,
    # with an empty string if the attribute was not found for that user.
    organized_data = {attr: {} for attr in attributes_to_extract}
    
    # Get a sorted list of all UIDs found in the dump for consistent output order
    all_uids_in_server_results = sorted(all_users_attributes.keys())

    for uid in all_uids_in_server_results:
        user_attrs = all_users_attributes[uid] # Get all attributes found for the current user
        for attr in attributes_to_extract:
            # For each requested attribute, get its value for the current user.
            # Use .get(attr, '') to return an empty string if the attribute is not found.
            organized_data[attr][uid] = user_attrs.get(attr, '')
    
    return organized_data

def sanitize_yaml_value(value):
    # Remove control characters (except tab, newline, carriage return)
    value = re.sub(r'[^\x09\x0A\x0D\x20-\x7E]', '', value)
    # Escape double quotes and backslashes
    value = value.replace('\\', '\\\\').replace('"', '\\"')
    return value

if __name__ == "__main__":
    # LDAP Connection Parameters - IMPORTANT: Customize these for your LDAP server!
    # For production use, consider loading these from environment variables or a secure configuration file.
    LDAP_HOST = 'lb.ldap.eparana.parana' # Replace with your LDAP server's hostname or IP address
    LDAP_PORT = 636        # Replace with your LDAP server's port (e.g., 636 for LDAPS)
    LDAP_SEARCH_BASE = 'dc=pr,dc=gov,dc=br' # Replace with the base DN for your search (e.g., 'ou=Users,dc=example,dc=com')
    LDAP_SEARCH_FILTER = '(objectClass=posixAccount)' # LDAP filter to select entries (e.g., all user accounts)
    LDAP_SCOPE = ldap.SCOPE_SUBTREE # Search scope: BASE, ONELEVEL, or SUBTREE
    LDAP_TIMEOUT = 600 # Timeout in seconds for LDAP operations (e.g., 10 minutes)

    print(f"Attempting to connect to LDAP server: {LDAP_HOST}:{LDAP_PORT}")
    print(f"Searching base DN: '{LDAP_SEARCH_BASE}' with filter: '{LDAP_SEARCH_FILTER}'")
    print(f"LDAP operation timeout set to: {LDAP_TIMEOUT} seconds")    

    ldap_connection = None # Initialize connection variable to None
    try:
        # Initialize LDAP connection
        # Use ldaps:// for port 636 (LDAP over SSL/TLS)
        ldap_connection = ldap.initialize(f"ldaps://{LDAP_HOST}:{LDAP_PORT}")
        # Set options (e.g., to disable referrals, which can cause issues in some environments)
        ldap_connection.set_option(ldap.OPT_REFERRALS, 0)
        # Set protocol version (optional, but good practice)
        ldap_connection.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
        # If using LDAPS and you need to disable certificate validation for testing (NOT recommended for production)
        # ldap_connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        # Set a network timeout for all LDAP operations
        ldap_connection.set_option(ldap.OPT_NETWORK_TIMEOUT, LDAP_TIMEOUT)

        # --- First Pass: Discover all available attributes ---
        print("\n--- First Pass: Discovering all available attributes ---")
        discovered_attributes = set()
        # Perform a search requesting no specific attributes (or an empty list)
        # This typically returns all attributes for the entries found.
        # We'll limit the search to a smaller number of entries for discovery
        # to avoid fetching all data twice if the directory is very large.
        # For a full discovery, you might remove the sizelimit.
        discovery_results = ldap_connection.search_s(
            LDAP_SEARCH_BASE,
            LDAP_SCOPE,
            LDAP_SEARCH_FILTER,
            attrlist=[], # Request all attributes
        )
        print(f"Discovered attributes from {len(discovery_results)} entries.")

        for dn, attrs in discovery_results:
            for key in attrs.keys():
                try:
                    # Decode attribute keys to strings before adding to the set
                    decoded_key = key.decode('utf-8') if isinstance(key, bytes) else key
                    discovered_attributes.add(decoded_key)
                except UnicodeDecodeError as e:
                    print(f"Warning: Could not decode attribute key '{key}' during discovery for DN '{dn}'. Error: {e}. Skipping this key.")
                except Exception as e:
                    print(f"Warning: An unexpected error occurred while processing attribute key '{key}' during discovery for DN '{dn}'. Error: {e}. Skipping this key.")

        # Convert the set of discovered attributes to a sorted list for consistent order
        attributes_to_extract = sorted(list(discovered_attributes))
        # Ensure 'uid' is always in the list, as it's critical for mapping
        if 'uid' not in attributes_to_extract:
            attributes_to_extract.insert(0, 'uid') # Add uid at the beginning if not found

        print(f"\nDiscovered attributes for extraction: {', '.join(attributes_to_extract)}")

    except ldap.SERVER_DOWN as e:
        print(f"LDAP Error: Could not connect to the LDAP server. Please check host, port, and network connectivity. Error: {e}")
        sys.exit(1)
    except ldap.NO_SUCH_OBJECT as e:
        print(f"LDAP Error: Search base '{LDAP_SEARCH_BASE}' not found. Error: {e}")
        sys.exit(1)
    except ldap.LDAPError as e:
        print(f"An LDAP error occurred: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)
    finally:
        # Always unbind from the LDAP server if a connection was established
        if ldap_connection:
            ldap_connection.unbind_s()
            print("Disconnected from LDAP server.")


    # --- Second Pass: Perform the main LDAP search with all discovered attributes ---
    # Re-establish connection for the second pass to avoid potential timeouts
    ldap_connection_second_pass = None
    try:
        print("\n--- Second Pass: Re-establishing LDAP connection for main search ---")
        ldap_connection_second_pass = ldap.initialize(f"ldaps://{LDAP_HOST}:{LDAP_PORT}")
        ldap_connection_second_pass.set_option(ldap.OPT_REFERRALS, 0)
        ldap_connection_second_pass.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
        ldap_connection_second_pass.set_option(ldap.OPT_NETWORK_TIMEOUT, LDAP_TIMEOUT)

        print("Performing main LDAP search and generating files...")
        # Perform the LDAP search for all entries within the search base, fetching all attributes.
        # The parsing function will then filter based on 'attributes_to_extract' and handle missing values.
        main_ldap_results = ldap_connection_second_pass.search_s(
            LDAP_SEARCH_BASE,
            LDAP_SCOPE,
            '(objectClass=*)', # Use a generic filter to fetch all entries within the search base
            attrlist=[], # Request all attributes for these entries
        )
        print(f"Found {len(main_ldap_results)} entries for full extraction.")

        # Pass the LDAP results to the parsing function
        extracted_data = parse_ldap_entries_and_extract_attributes(main_ldap_results, attributes_to_extract)

        if extracted_data:
            output_directory = "output_yaml_files"
            os.makedirs(output_directory, exist_ok=True)

            now_epoch = int(time.time())

            for attr_name, uid_value_map in extracted_data.items():
                # Write the normal attribute file
                output_filename = os.path.join(output_directory, f"{attr_name}.yml")
                try:
                    with open(output_filename, 'w', encoding='utf-8') as f_out:
                        for uid, value in uid_value_map.items():
                            clean_uid = sanitize_yaml_value(uid)
                            clean_value = sanitize_yaml_value(value)
                            f_out.write(f'"{clean_uid}": "{clean_value}"\n')
                    print(f"Successfully generated '{output_filename}'")
                except Exception as e:
                    print(f"Error writing to output file '{output_filename}': {e}")

                # If this attribute is in the epoch list, calculate age
                if attr_name in epoch_variables_calculate_age:
                    age_filename = os.path.join(output_directory, f"{attr_name}_age_in_seconds.yml")
                    try:
                        with open(age_filename, 'w', encoding='utf-8') as f_age:
                            for uid, value in uid_value_map.items():
                                clean_uid = sanitize_yaml_value(uid)
                                try:
                                    epoch_val = int(value)
                                    if epoch_val > 0:
                                        age_seconds = now_epoch - epoch_val
                                        f_age.write(f'"{clean_uid}": {age_seconds}\n')   # integer (no quotes)
                                    else:
                                        f_age.write(f'"{clean_uid}": null\n')            # YAML null
                                except ValueError:
                                    # Non-numeric or empty value → empty output
                                    f_age.write(f'"{clean_uid}": null\n')                # YAML null
                        print(f"Successfully generated '{age_filename}'")
                    except Exception as e:
                        print(f"Error writing to output file '{age_filename}': {e}")


    except ldap.SERVER_DOWN as e:
        print(f"LDAP Error (Second Pass): Could not connect to the LDAP server. Please check host, port, and network connectivity. Error: {e}")
        sys.exit(1)
    except ldap.NO_SUCH_OBJECT as e:
        print(f"LDAP Error (Second Pass): Search base '{LDAP_SEARCH_BASE}' not found. Error: {e}")
        sys.exit(1)
    except ldap.LDAPError as e:
        print(f"An LDAP error occurred during the second pass: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during the second pass: {e}")
        sys.exit(1)
    finally:
        # Always unbind from the LDAP server after the second pass
        if ldap_connection_second_pass:
            ldap_connection_second_pass.unbind_s()
            print("Disconnected from LDAP server after second pass.")
