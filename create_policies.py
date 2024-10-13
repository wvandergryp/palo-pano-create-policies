#!/usr/bin/env python
# Import the Panorama module from the pandevice library
from pandevice import panorama

# Import the argparse module for parsing command line arguments
import argparse

# Import the policies module from the pandevice library
from pandevice import policies

# Import the SecurityRule class from the pandevice.policies module
from pandevice.policies import SecurityRule  # Ensure all rulebases are imported

# Import the csv module for reading CSV files
import csv

# Import the sys module for system-specific parameters and functions
import sys

def safe_split(value):
    """Utility function to split values only if not empty."""
    return value.split(" ") if value else []

if __name__ == '__main__':
    try:
        # Parse command line arguments
        print("Parsing command line arguments...")
        parser = argparse.ArgumentParser()
        parser.add_argument("hostname", help="Hostname of the Panorama device")
        parser.add_argument("device_group_name", help="Device Group Name")
        parser.add_argument("userid", help="User ID for the Panorama device")
        parser.add_argument("password", help="Password for the Panorama device")
        parser.add_argument("rule_file", help="Path to the CSV file containing the security rules", default="all.csv")

        args = parser.parse_args()
        print(f"Arguments parsed: hostname={args.hostname}, Location={args.device_group_name}")

        # Extract the rule file path from the command line arguments
        rule_file = args.rule_file

        print("Creating Panorama object...")
        # Create a Panorama object
        panorama_prod = panorama.Panorama(args.hostname, args.userid, args.password)
        print("Panorama object created successfully.")

        device_group = panorama.DeviceGroup(args.device_group_name)
        print (f"Device Group Name: {device_group}")

        # Loop through all the devices and print their names
        print("Fetching devices...")
        devices = panorama_prod.refresh_devices()
        print (f"Devices: {devices}")
        device_exist = False
        for device in devices:
            print(f"Device Name: {device.name}")
            if args.device_group_name in device.name:
                device_exist = True
            else:
                device_exist = False
        if device_exist == False:
                print(f"Device group '{args.device_group_name}' does not exist. Exiting...")
                sys.exit(0)
        panorama_prod.add(device_group)
        rulebase = policies.PreRulebase()  # Adjust if using different rulebase
        device_group.add(rulebase)

        # Refresh the rulebase to get existing rules
        print("Fetching existing rules...")
        existing_rules = SecurityRule.refreshall(rulebase)

        existing_rule_names = [rule.name for rule in existing_rules]

        # Open the CSV file and read its contents
        with open(rule_file, 'r') as file_:
            csv_reader = csv.reader(file_)
            header = next(csv_reader)  # Skip the header row

            for row in csv_reader:
                if len(row) < 17:
                    print(f"Skipping incomplete row (expected 17 columns, got {len(row)}): {row}")
                    continue  # Skip rows that do not have the expected number of columns

                # Extract and clean data from CSV
                device_group_name = row[0] if row[0] else None
                rule_name = row[1] if row[1] else None
                rule_type = row[2] if row[2] else None
                description = row[3] if row[3] else None
                tags = safe_split(row[4])
                group_rules_by_tag = row[5] if row[5] else None
                audit_commit = row[6].lower() == 'true' if row[6] else False
                source_zone = safe_split(row[7])
                source_address = safe_split(row[8])
                destination_zone = safe_split(row[9])
                destination_address = safe_split(row[10])
                application = safe_split(row[11])
                services = safe_split(row[12])
                action = row[13] if row[13] else None
                profile_type = row[14] if row[14] else None
                group_profile = row[15] if row[15] else None
                log_settings = row[16] if row[16] else None

                # Create the security rule only if necessary fields are provided
                if rule_name:
                    security_rule_params = {
                        'name': rule_name,
                        'fromzone': source_zone if source_zone else None,
                        'source': source_address if source_address else None,
                        'tozone': destination_zone if destination_zone else None,
                        'destination': destination_address if destination_address else None,
                        'application': application if application else None,
                        'service': services if services else None,
                        'action': action if action else None,
                        'description': description,
                        'tag': tags if tags else None,
                        'log_setting': log_settings if log_settings else None
                    }

                    # Filter out None values from parameters
                    security_rule_params = {k: v for k, v in security_rule_params.items() if v is not None}

                    # Check if the rule already exists in the fetched list
                    if rule_name in existing_rule_names:
                        print(f"Rule '{rule_name}' already exists. Skipping creation.")
                        continue

                    # Create and add the security rule
                    security_rule = policies.SecurityRule(**security_rule_params)
                    rulebase.add(security_rule)
                    security_rule.create()
                    print(f"Rule '{rule_name}' created successfully in device group '{device_group_name}'.")

        # Optionally, commit to Panorama if required (commented out for manual commit)
        # print("Committing changes to Panorama...")
        # panorama_prod.commit()
        # print("Commit successful.")

    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(0)
