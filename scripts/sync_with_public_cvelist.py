#!/usr/bin/python
import argparse
import os
import shutil

from . import utils


def setup_opts():
    parser = argparse.ArgumentParser(
        description='Update the internal cvelist from '
        'the public cvelist.')
    parser.add_argument('-p', '--path-to-cvelist-repository',
                        dest='public_cvelist_path', required=True,
                        help='Path to the public cvelist repository.')
    return parser


def main():
    args = setup_opts().parse_args()
    internal_cvelist = utils.get_internal_cvelist_location()
    files_to_match = []
    for cve_id in utils.get_our_cna_cve_ids():
        files_to_match.append('%s.json' % cve_id)
    files = set(utils.get_file_listing_for_path(args.public_cvelist_path,
                                                files_to_match))
    for a_file in files:
        a_dir = os.path.dirname(a_file).split('cvelist')[-1].lstrip(os.sep)
        dest = os.path.join(internal_cvelist, a_dir)
        base_name = os.path.basename(a_file)
        existing_json_data = utils.get_info_from_cve_json_file(a_file)
        state = utils.get_state_from_cve_json(existing_json_data)
        if state == 'RESERVED':
            possible_existing_location = os.path.join(dest, base_name)
            if os.path.exists(possible_existing_location):
                print('Not copying %s as it already exists at %s' % (
                      a_file, possible_existing_location))
                continue
            dest = os.path.join(dest, 'reserved')
        if state not in {'RESERVED', 'PUBLIC'}:
            raise ValueError('%s is not a valid state - %s' % (state, a_file))
        os.makedirs(dest, exist_ok=True)
        dest_file = os.path.join(dest, base_name)
        shutil.copy(a_file, dest_file)


if __name__ == '__main__':
    main()
