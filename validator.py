#!/usr/bin/python
import os
import sys

import jsonschema
import requests

from scripts import utils


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
            if not file_.endswith('.json'):
                continue
            file_json = utils.get_info_from_cve_json_file(full_path)
            if 'CVE-' not in file_ or 'templates' in full_path:
                continue
            state = utils.get_state_from_cve_json(file_json)
            if state == 'RESERVED':
                schema = 'CVE_JSON_4.0_min_reserved.schema'
            if state not in {'RESERVED', 'PUBLIC', 'IN_PROGRESS'}:
                print(full_path, state, 'is not a valid STATE value.')
                errors += 1
            cve_id = utils.get_cve_id_from_cve_json(file_json)
            cve_id_from_fn = os.path.basename(full_path).split('.json')[0]
            if cve_id != cve_id_from_fn:
                print(full_path, cve_id,
                      'does not match the file name cve id', cve_id_from_fn)
                errors += 1
            validator = jsonschema.Draft4Validator(schema_data[schema])
            if not validator.is_valid(file_json):
                errors += 1
                print(full_path, 'has failed validation.')
                for error in validator.iter_errors(file_json):
                    print(error.message)
    sys.exit(errors)


if __name__ == '__main__':
    main()
