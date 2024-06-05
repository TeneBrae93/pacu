#!/usr/bin/env python3
import argparse
import sys

# Import the enumerate-iam library from core
from pacu.core.enumerate_iam.main import enumerate_iam

module_info = {
    'name': 'iam__bruteforce_permissions',
    'author': 'Alexander Morgenstern at RhinoSecurityLabs',
    'category': 'ENUM',
    'one_liner': 'Enumerates permissions using brute force',
    'description': "This module will automatically run through all possible API calls of supported services in order to enumerate permissions without the use of the IAM API.",
    'services': ['all'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--services'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument(
    '--services',
    required=False,
    default=None,
    help='A comma separated list of services to brute force permissions'
)

def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print

    aws_key = session.get_active_aws_key(pacu_main.database)

    access_key = aws_key.access_key_id
    secret_key = aws_key.secret_access_key
    session_token = aws_key.session_token if aws_key.session_token else None
    region = 'us-east-1'  # You can change this to the desired region

    # Call the enumerate_iam function from the enumerate-iam library
    results = enumerate_iam(
        access_key=access_key,
        secret_key=secret_key,
        session_token=session_token,
        region=region
    )

    # Process and print the results
    print('Enumerated IAM Permissions:')
    for service, actions in results.items():
        print(f'{service}:')
        for action, status in actions.items():
            print(f'  {action}: {status}')

    return results

def summary(data, pacu_main):
    out = 'Services: \n'
    out += '  Supported: {}.\n'.format(data['services'])
    if 'unsupported' in data:
        out += '  Unsupported: {}.\n'.format(data['unsupported'])
    if 'unknown' in data:
        out += '  Unknown: {}.\n'.format(data['unknown'])
    out += '{} allow permissions found.\n'.format(data['allow'])
    out += '{} unknown permissions found.\n'.format(data['unknown'])
    out += '{} deny permissions found.\n'.format(data['deny'])
    return out
