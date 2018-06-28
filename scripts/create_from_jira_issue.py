#!/usr/bin/python
import argparse
import json

import requests


def setup_opts():
    parser = argparse.ArgumentParser(description='CVE id json creator')
    parser.add_argument('-u', '--url', dest='jira_server_url',
                        required=True, help='Url to the jira server')
    parser.add_argument('-i', '--issue-key', dest='issue_key',
                        required=True, help='The jira issue key')
    return parser


def main():
    base = None
    with open('templates/base.json', 'r') as f:
        base = json.load(f)
    args = setup_opts().parse_args()
    url = args.jira_server_url + '/rest/api/latest/issue/' + args.issue_key
    reference_link = args.jira_server_url + '/browse/' + args.issue_key
    issue = requests.get(url).json()
    fields = issue['fields']
    project_name = fields['project']['name']
    description = fields['description']
    fixed_versions = fields.get('fixVersions', [])
    product_data = (base['affects']['vendor']['vendor_data'][0]
                    ['product']['product_data'][0])
    if fixed_versions and len(fixed_versions) == 1:
        product_data['version']['version_data'] = [{
            'version_value': fixed_versions[0]['name'],
            'version_affected': '<',
        }]
    if 'xss' in set(fields['labels']):
        base['problemtype']['problemtype_data'][0]['description'][
            0]['value'] = "Cross Site Scripting (XSS)"
    product_data['product_name'] = project_name
    base['description']['description_data'][0]['value'] = description
    base['references']['reference_data'][0]['url'] = reference_link
    print(json.dumps(base, indent=3))


if __name__ == '__main__':
    main()
