#!/usr/bin/python
import json
import os
import sys

import jsonschema
import requests


def retrieve_schema(schemas):
    url_format = ('https://github.com/CVEProject/automation-working-group'
                  '/raw/master/cve_json_schema/%s')
    schema_data = {}
    for url in schemas:
        response = requests.get(url_format % url)
        response.raise_for_status()
        schema_data[url] = response.json()
    return schema_data


def main():
    errors = 0
    schemas = ['CVE_JSON_4.0_min_public.schema',
               'CVE_JSON_4.0_min_reserved.schema']
    schema_data = retrieve_schema(schemas)
    for root, dirs, files in os.walk('.'):
        for file_ in sorted(files, reverse=True):
            schema = 'CVE_JSON_4.0_min_public.schema'
            full_path = os.path.join(root, file_)
            file_json = None
            if (not file_.endswith('.json') or
                    'templates' in full_path or 'CVE-' not in file_):
                continue
            with open(full_path, 'r') as f:
                file_json = json.load(f)
            if '/reserved/' in full_path:
                schema = 'CVE_JSON_4.0_min_reserved.schema'
            validator = jsonschema.Draft4Validator(schema_data[schema])
            if not validator.is_valid(file_json):
                errors += 1
                print(full_path, 'has failed validation.')
                for error in validator.iter_errors(file_json):
                    print(error.message)
    sys.exit(errors)


if __name__ == '__main__':
    main()
