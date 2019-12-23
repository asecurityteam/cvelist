#!/usr/bin/python
import os
import json
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


def create_missing_cve_id_files():
    internal_cvelist = utils.get_internal_cvelist_location()
    template = None
    with open(os.path.join(internal_cvelist, 'templates', 'reserved.json'),
              'r') as f:
        template = json.load(f)
    for cve_id in utils.get_our_cna_cve_ids():
        cve_id_f_name = '%s.json' % cve_id
        _, cve_id_year, cve_id_num = cve_id.split('-')
        cve_id_num = int(cve_id_num)
        cve_id_num_dir_name = '%sxxx' % int((cve_id_num / 1000))
        expected_path = os.path.join(
            internal_cvelist, cve_id_year, cve_id_num_dir_name)
        expected_path_f = os.path.join(expected_path, cve_id_f_name)
        if not os.path.exists(expected_path_f):
            os.makedirs(expected_path, exist_ok=True)
            template_to_modify = template.copy()
            template_to_modify['CVE_data_meta']['ID'] = cve_id
            with open(expected_path_f, 'w+') as f:
                json.dump(template_to_modify, f, indent=4)


def main():
    create_missing_cve_id_files()
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
